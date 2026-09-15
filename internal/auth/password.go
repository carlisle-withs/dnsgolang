package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword 生成 bcrypt 口令散列。
// 说明:原系统使用 Django PBKDF2,算法不兼容——全新 schema 全新密码,
// 存量用户需重设(技术方案 5.2 已决策)。
func HashPassword(plain string) (string, error) {
	data, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(data), err
}

// CheckPassword 校验口令。
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
