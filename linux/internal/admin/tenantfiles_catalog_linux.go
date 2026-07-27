package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const tenantProductionSystemdRoot = "/etc/systemd/system"

// TenantFileCatalogTransaction is an unforgeable, callback-scoped capability
// for changing the tenant configuration catalog. Its methods reject the zero
// value and a token retained after the callback. The exclusive catalog guard
// remains held across publication, one batch daemon-reload, and loaded-unit
// verification.
type TenantFileCatalogTransaction struct {
	guard  io.Closer
	active bool
}

type tenantFileCatalogAcquire func(context.Context) (io.Closer, error)

func WithTenantFileCatalogTransaction(ctx context.Context, operation func(*TenantFileCatalogTransaction) error) error {
	if os.Geteuid() != 0 {
		return errors.New("tenant configuration updates require root")
	}
	return withTenantFileCatalogTransaction(ctx, func(ctx context.Context) (io.Closer, error) {
		return lifecyclelock.AcquireCatalogExclusive(ctx)
	}, operation)
}

func withTenantFileCatalogTransaction(ctx context.Context, acquire tenantFileCatalogAcquire, operation func(*TenantFileCatalogTransaction) error) (resultErr error) {
	if ctx == nil || acquire == nil || operation == nil {
		return errors.New("tenant file catalog transaction is unavailable")
	}
	guard, err := acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant configuration lifecycle lock: %w", err)
	}
	if nilTenantFileCatalogGuard(guard) {
		return errors.New("tenant configuration lifecycle lock acquisition returned no guard")
	}
	transaction := &TenantFileCatalogTransaction{guard: guard, active: true}
	defer func() {
		transaction.active = false
		transaction.guard = nil
		resultErr = errors.Join(resultErr, guard.Close())
	}()
	return operation(transaction)
}

func nilTenantFileCatalogGuard(guard io.Closer) bool {
	if guard == nil {
		return true
	}
	value := reflect.ValueOf(guard)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (transaction *TenantFileCatalogTransaction) requireActive() error {
	if transaction == nil || !transaction.active || transaction.guard == nil {
		return errors.New("tenant file catalog transaction capability is inactive")
	}
	return nil
}

// UpdateTenantFiles validates the complete batch before its first mutation,
// publishes every tenant under one C_EX, reloads systemd exactly once, and
// verifies every loaded service before returning.
func (transaction *TenantFileCatalogTransaction) UpdateTenantFiles(ctx context.Context, portal config.Portal, tenants []config.Tenant, controller systemdctl.Controller) error {
	return transaction.updateTenantFilesWithHook(ctx, portal, tenants, controller, nil)
}

func (transaction *TenantFileCatalogTransaction) updateTenantFilesWithHook(ctx context.Context, portal config.Portal, tenants []config.Tenant, controller systemdctl.Controller, hook tenantFileFaultHook) error {
	if err := transaction.requireActive(); err != nil {
		return err
	}
	if ctx == nil || len(tenants) == 0 || len(tenants) > 10000 {
		return errors.New("tenant file update batch is invalid")
	}
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	// An older durable intent has priority over every property of the newly
	// requested generation. Converge, reload, verify, and durably commit it
	// before inspecting or preparing the new tenant batch.
	if _, err := transaction.ReconcilePendingTenantFiles(ctx, portal, controller); err != nil {
		return fmt.Errorf("reconcile older tenant file transaction before new update: %w", err)
	}
	current, err := loadFinalTenantFileCatalog(portal, nil)
	if err != nil {
		return fmt.Errorf("load clean tenant catalog before full-generation update: %w", err)
	}
	ordered, err := mergeTenantFileCatalog(current, tenants)
	if err != nil {
		return err
	}
	publications := make([]tenantFilePublication, 0, len(ordered))
	for _, tenant := range ordered {
		publication, err := prepareTenantFilePublication(portal, tenant, tenantProductionSystemdRoot)
		if err != nil {
			return fmt.Errorf("prepare tenant %s file publication: %w", tenant.TenantID, err)
		}
		publications = append(publications, publication)
	}
	// Prove anonymous-inode support on every protected filesystem before the
	// global batch intent or any directory/ACL mutation becomes visible.
	for _, publication := range publications {
		if err := probeTenantFileAnonymousCapabilities(publication.plan); err != nil {
			return err
		}
	}
	batch, err := makeTenantFileBatchJournal(portal, tenantProductionSystemdRoot, publications)
	if err != nil {
		return err
	}
	if err := writeTenantFileBatchJournalWithHook(portal, tenantProductionSystemdRoot, batch, hook); err != nil {
		return err
	}
	if err := reconcileTenantFileBatchWithHook(ctx, portal, tenantProductionSystemdRoot, batch, hook); err != nil {
		return fmt.Errorf("publish tenant batch files: %w", err)
	}
	if _, _, err := finalizeTenantFileCatalogWithHook(ctx, portal, tenantProductionSystemdRoot, controller, &batch, hook); err != nil {
		return err
	}
	// Durable unlink is the final commit, after complete file convergence, one
	// daemon-reload, every tenant readback, and exact service/socket equality.
	if err := removeTenantFileBatchJournalWithHook(portal, tenantProductionSystemdRoot, batch, hook); err != nil {
		return fmt.Errorf("commit verified tenant batch transaction: %w", err)
	}
	return nil
}

func mergeTenantFileCatalog(current, requested []config.Tenant) ([]config.Tenant, error) {
	if len(requested) == 0 || len(requested) > 10000 || len(current) > 10000 {
		return nil, errors.New("tenant file update batch is invalid")
	}
	merged := make(map[string]config.Tenant, len(current)+len(requested))
	for _, tenant := range current {
		if tenant.TenantID == "" || merged[tenant.TenantID].TenantID != "" {
			return nil, errors.New("current tenant file catalog contains a duplicate identity")
		}
		merged[tenant.TenantID] = tenant
	}
	seenRequested := make(map[string]bool, len(requested))
	for _, tenant := range requested {
		if tenant.TenantID == "" || seenRequested[tenant.TenantID] {
			return nil, errors.New("tenant file update batch contains a duplicate tenant")
		}
		seenRequested[tenant.TenantID] = true
		merged[tenant.TenantID] = tenant
	}
	if len(merged) == 0 || len(merged) > 10000 {
		return nil, errors.New("final tenant file catalog size is invalid")
	}
	ordered := make([]config.Tenant, 0, len(merged))
	for _, tenant := range merged {
		ordered = append(ordered, tenant)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].TenantID < ordered[j].TenantID })
	return ordered, nil
}

// UpdateTenantFiles opens one exclusive catalog transaction for a complete
// tenant batch. Callers that need an in-lock rollback use
// WithTenantFileCatalogTransaction and invoke the method above directly.
func UpdateTenantFiles(ctx context.Context, portal config.Portal, tenants []config.Tenant, controller systemdctl.Controller) error {
	return WithTenantFileCatalogTransaction(ctx, func(transaction *TenantFileCatalogTransaction) error {
		return transaction.UpdateTenantFiles(ctx, portal, tenants, controller)
	})
}

// WriteTenantFiles retains the single-tenant API while enforcing the same
// publication -> daemon-reload -> VerifyTenantService C_EX boundary as batch
// production callers.
func WriteTenantFiles(ctx context.Context, portal config.Portal, tenant config.Tenant) error {
	return UpdateTenantFiles(ctx, portal, []config.Tenant{tenant}, nil)
}
