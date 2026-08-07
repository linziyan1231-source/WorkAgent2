package portal

import "testing"

func TestValidMarketSkillNameAllowsSafeUnicode(t *testing.T) {
	for _, name := range []string{"professional-database", "专业数据库", "财务 分析"} {
		if !validMarketSkillName(name) {
			t.Fatalf("expected valid market skill name %q", name)
		}
	}
}

func TestValidMarketSkillNameRejectsUnsafeWindowsNames(t *testing.T) {
	for _, name := range []string{"", " ../escape", "../escape", `nested/skill`, `nested\skill`, "skill..name", "skill.", "skill*", "CON", "com1.md", "con.txt.extra", "line\nbreak"} {
		if validMarketSkillName(name) {
			t.Fatalf("expected invalid market skill name %q", name)
		}
	}
}
