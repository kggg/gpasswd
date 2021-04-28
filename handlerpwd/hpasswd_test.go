package handlerpwd

import (
	"testing"
)

func TestGenerateRandPasswd(t *testing.T) {

	pass := GenerateRandPasswd()
	t.Log(pass)
}

func TestAesEncrypt(t *testing.T) {
	str := "hello"
	epass, err := AesDecrypt(str)
	if err != nil {
		t.Error(err)
	}
	t.Log(epass)

}
