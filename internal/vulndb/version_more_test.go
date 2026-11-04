package vulndb

import "testing"

func TestPEP440Compare(t *testing.T) {
	asc := []string{"1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1.1", "2!0.1"}
	for i := 0; i+1 < len(asc); i++ {
		if PEP440Compare(asc[i], asc[i+1]) >= 0 || PEP440Compare(asc[i+1], asc[i]) <= 0 {
			t.Errorf("want %s < %s", asc[i], asc[i+1])
		}
	}
	for _, eq := range [][2]string{{"1.0", "1.0.0"}, {"v4.2", "4.2"}, {"1.0+local", "1.0"}} {
		if PEP440Compare(eq[0], eq[1]) != 0 {
			t.Errorf("want %s == %s", eq[0], eq[1])
		}
	}
}

func TestGemCompare(t *testing.T) {
	asc := []string{"1.0.a", "1.0.b1", "1.0", "1.0.1", "1.10", "7.0.8.4"}
	for i := 0; i+1 < len(asc); i++ {
		if GemCompare(asc[i], asc[i+1]) >= 0 || GemCompare(asc[i+1], asc[i]) <= 0 {
			t.Errorf("want %s < %s", asc[i], asc[i+1])
		}
	}
	if GemCompare("1.0", "1.0.0") != 0 {
		t.Error("want 1.0 == 1.0.0")
	}
}

func TestPyPIName(t *testing.T) {
	if PyPIName("Flask_SQLAlchemy") != "flask-sqlalchemy" || PyPIName("zope.interface") != "zope-interface" {
		t.Error("PEP 503 normalisation failed")
	}
}
