package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/hkdf"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
)

const (
	backupMagic = "WABKUP01"
	chunkSize   = 1024 * 1024
	keySize     = 32
	headerSize  = len(backupMagic) + 32 + 8
)

func GenerateKey(path string) error {
	if !cleanAbsolute(path) {
		return errors.New("backup key path must be clean and absolute")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("refusing to overwrite an existing backup key")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	defer clear(key)
	payload := append([]byte(base64.RawStdEncoding.EncodeToString(key)), '\n')
	defer clear(payload)
	return atomicWriteNoReplace(path, payload, 0o600)
}

func LoadKey(path string, requireRootOwner bool) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("backup key path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1024 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("backup key is missing or unsafe")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("backup key is not owned by root")
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("backup key could not be read")
	}
	before, err := file.Stat()
	beforeStat, beforeOK := fileSyscallStat(before)
	infoStat, infoOK := fileSyscallStat(info)
	if err != nil || !beforeOK || !infoOK || !sameArchivedStat(infoStat, beforeStat) {
		file.Close()
		return nil, errors.New("backup key changed while it was opened")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 1025))
	after, statErr := file.Stat()
	afterStat, afterOK := fileSyscallStat(after)
	closeErr := file.Close()
	named, namedErr := os.Lstat(path)
	namedStat, namedOK := fileSyscallStat(named)
	if readErr != nil || len(payload) > 1024 || statErr != nil || !afterOK || closeErr != nil || namedErr != nil || !namedOK ||
		!sameArchivedStat(beforeStat, afterStat) || !sameArchivedStat(beforeStat, namedStat) {
		clear(payload)
		return nil, errors.New("backup key changed while it was read")
	}
	defer clear(payload)
	value := strings.TrimSpace(string(payload))
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(key) != keySize {
		clear(key)
		return nil, errors.New("backup key is invalid")
	}
	return key, nil
}

type encryptWriter struct {
	destination io.Writer
	aead        cipher.AEAD
	header      []byte
	noncePrefix [8]byte
	counter     uint32
	buffer      []byte
	closed      bool
}

func newEncryptWriter(destination io.Writer, masterKey []byte) (*encryptWriter, error) {
	if destination == nil || len(masterKey) != keySize {
		return nil, errors.New("invalid backup encryption parameters")
	}
	salt := make([]byte, 32)
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, err
	}
	derived := make([]byte, keySize)
	reader := hkdf.New(sha256.New, masterKey, salt, []byte("WorkAgent2 WorkAgent backup encryption v1"))
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, headerSize)
	header = append(header, backupMagic...)
	header = append(header, salt...)
	header = append(header, prefix...)
	if _, err := destination.Write(header); err != nil {
		return nil, err
	}
	value := &encryptWriter{destination: destination, aead: aead, header: header, buffer: make([]byte, 0, chunkSize)}
	copy(value.noncePrefix[:], prefix)
	return value, nil
}

func (w *encryptWriter) Write(payload []byte) (int, error) {
	if w.closed {
		return 0, errors.New("backup encryption stream is closed")
	}
	written := 0
	for len(payload) > 0 {
		available := chunkSize - len(w.buffer)
		if available > len(payload) {
			available = len(payload)
		}
		w.buffer = append(w.buffer, payload[:available]...)
		payload = payload[available:]
		written += available
		if len(w.buffer) == chunkSize {
			if err := w.seal(w.buffer); err != nil {
				return written, err
			}
			w.buffer = w.buffer[:0]
		}
	}
	return written, nil
}

func (w *encryptWriter) Close() error {
	if w.closed {
		return nil
	}
	if len(w.buffer) > 0 {
		if err := w.seal(w.buffer); err != nil {
			return err
		}
		w.buffer = w.buffer[:0]
	}
	if err := w.seal(nil); err != nil {
		return err
	}
	w.closed = true
	clear(w.buffer)
	return nil
}

func (w *encryptWriter) seal(plaintext []byte) error {
	nonce, additional := recordMaterial(w.header, w.noncePrefix, w.counter, uint32(len(plaintext)))
	ciphertext := w.aead.Seal(nil, nonce, plaintext, additional)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(plaintext)))
	if _, err := w.destination.Write(length[:]); err != nil {
		return err
	}
	if _, err := w.destination.Write(ciphertext); err != nil {
		return err
	}
	if w.counter == ^uint32(0) {
		return errors.New("backup encryption stream is too large")
	}
	w.counter++
	return nil
}

type decryptReader struct {
	source      io.Reader
	aead        cipher.AEAD
	header      []byte
	noncePrefix [8]byte
	counter     uint32
	plaintext   []byte
	final       bool
	failure     error
}

func newDecryptReader(source io.Reader, masterKey []byte) (*decryptReader, error) {
	if source == nil || len(masterKey) != keySize {
		return nil, errors.New("invalid backup decryption parameters")
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(source, header); err != nil || string(header[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("backup encryption header is invalid")
	}
	salt := header[len(backupMagic) : len(backupMagic)+32]
	prefix := header[len(backupMagic)+32:]
	derived := make([]byte, keySize)
	reader := hkdf.New(sha256.New, masterKey, salt, []byte("WorkAgent2 WorkAgent backup encryption v1"))
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	value := &decryptReader{source: source, aead: aead, header: header}
	copy(value.noncePrefix[:], prefix)
	return value, nil
}

func (r *decryptReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if len(r.plaintext) == 0 && !r.final && r.failure == nil {
		r.loadRecord()
	}
	if len(r.plaintext) > 0 {
		n := copy(destination, r.plaintext)
		r.plaintext = r.plaintext[n:]
		return n, nil
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if r.final {
		return 0, io.EOF
	}
	return 0, errors.New("backup decryption made no progress")
}

func (r *decryptReader) loadRecord() {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(r.source, lengthBytes[:]); err != nil {
		r.failure = errors.New("encrypted backup is truncated")
		return
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length > chunkSize {
		r.failure = errors.New("encrypted backup record is too large")
		return
	}
	ciphertext := make([]byte, int(length)+r.aead.Overhead())
	if _, err := io.ReadFull(r.source, ciphertext); err != nil {
		r.failure = errors.New("encrypted backup is truncated")
		return
	}
	nonce, additional := recordMaterial(r.header, r.noncePrefix, r.counter, length)
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, additional)
	clear(ciphertext)
	if err != nil {
		r.failure = errors.New("encrypted backup authentication failed")
		return
	}
	if r.counter == ^uint32(0) {
		clear(plaintext)
		r.failure = errors.New("encrypted backup has too many records")
		return
	}
	r.counter++
	if length == 0 {
		var trailing [1]byte
		n, err := r.source.Read(trailing[:])
		if n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
			r.failure = errors.New("encrypted backup contains trailing data")
			return
		}
		r.final = true
		return
	}
	r.plaintext = plaintext
}

func (r *decryptReader) Complete() error {
	buffer := make([]byte, 32*1024)
	for {
		_, err := r.Read(buffer)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if !r.final {
		return errors.New("encrypted backup has no authenticated end marker")
	}
	return nil
}

func recordMaterial(header []byte, prefix [8]byte, counter, length uint32) ([]byte, []byte) {
	nonce := make([]byte, 12)
	copy(nonce, prefix[:])
	binary.BigEndian.PutUint32(nonce[8:], counter)
	additional := make([]byte, 0, len(header)+8)
	additional = append(additional, header...)
	var value [8]byte
	binary.BigEndian.PutUint32(value[:4], counter)
	binary.BigEndian.PutUint32(value[4:], length)
	additional = append(additional, value[:]...)
	return nonce, additional
}

func atomicWrite(path string, payload []byte, mode os.FileMode) error {
	return atomicWriteWithPublication(path, payload, mode, false)
}

func atomicWriteNoReplace(path string, payload []byte, mode os.FileMode) error {
	return atomicWriteWithPublication(path, payload, mode, true)
}

func atomicWriteWithPublication(path string, payload []byte, mode os.FileMode, noReplace bool) error {
	if noReplace && !cleanAbsolute(path) {
		return errors.New("no-replace publication path is invalid")
	}
	err := fsutil.WriteFileAtomic(path, payload, fsutil.AtomicWriteOptions{
		Mode: mode, NoReplace: noReplace, TempPattern: ".workagent-backup-*",
		CheckParent: true, SafeParent: true, WrapDirSync: true,
	})
	if errors.Is(err, fsutil.ErrUnsafeParent) {
		return errors.New("atomic-write parent is missing or unsafe")
	}
	if errors.Is(err, fsutil.ErrTargetExists) {
		return errors.New("refusing to overwrite existing state")
	}
	return err
}
