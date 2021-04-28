package handlerpwd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/rand"
	"time"
)

const (
	passwdLength = 8
	RandSeed     = "abcdefhijklmnopqrstuvwzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789wfert"
)

var (
	AESKey = []byte("abcdefghijklmnop")
)

func GenerateRandPasswd() string {
	var passwd []byte = make([]byte, passwdLength, passwdLength)
	//call rand.Seed() with a seed value in order to initialize the random number generator.
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < passwdLength; i++ {
		index := rand.Intn(len(RandSeed))
		passwd[i] = RandSeed[index]
	}
	return string(passwd)
}

func RandomString(l int) string {
	str := "kl0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length < 1 {
		return nil, errors.New("the cipther length less than 1")
	}
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)], nil
}

func AesEncrypt(str string) (string, error) {
	origData := []byte(str)
	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, AESKey[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	//encodestring := base64.StdEncoding.EncodeToString(crypted)
	//return encodestring, nil
	return hex.EncodeToString(crypted), nil

}

func AesDecrypt(crypted string) (string, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, AESKey[:blockSize])
	origData := make([]byte, len(decodeBytes))
	blockMode.CryptBlocks(origData, decodeBytes)
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return "", err
	}
	decryptstr := string(origData)
	return decryptstr, nil
}
