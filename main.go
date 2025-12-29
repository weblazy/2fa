package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"github.com/urfave/cli/v2"
	"github.com/weblazy/crypto/aes"
	"github.com/weblazy/crypto/mode"
	"github.com/weblazy/easy/csvx"
)

var (
	aesKey = os.Getenv("AES_KEY")
	file   = os.Getenv("FA_PATH")
)

const preferenceCurrentTutorial = "currentTutorial"

var topWindow fyne.Window

func main() {
	// 打印Banner
	projectName := "Security"
	// 配置cli参数
	app := cli.NewApp()
	app.Name = projectName
	app.Usage = projectName
	app.Version = "1.0.0"

	// 指定命令运行的函数
	app.Commands = []*cli.Command{
		{
			Name:    "2fa",
			Aliases: []string{"2"},
			Usage:   "sec 2fa",
			Action:  TowFA,
		},
		{
			Name:    "encrypt",
			Aliases: []string{"enc"},
			Usage:   "sec enc -t text",
			Action:  Encrypt,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "text",
					Aliases: []string{"t"},
					Usage:   "text",
					Value:   "",
				},
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"dec"},
			Usage:   "sec dec -k key",
			Action:  Decrypt,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "key",
					Aliases: []string{"k"},
					Usage:   "key",
					Value:   "",
				},
			},
		},
		{
			Name:    "view",
			Aliases: []string{"v"},
			Usage:   "sec v",
			Action:  View,
			Flags:   []cli.Flag{},
		},
	}

	// 启动cli
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%#v\n", err)
	}
}

// all []byte in this program are treated as Big Endian
func TowFA(c *cli.Context) error {
	csv, err := csvx.NewCSV(file, ',', "\n")
	if err != nil {
		return err
	}
	defer func() {
		_ = csv.Close()
	}()
	text := ""
	epochSeconds := time.Now().Unix()
	secondsRemaining := 30 - (epochSeconds % 30)
	for row, err := csv.ReadLine(); err == nil; row, err = csv.ReadLine() {
		if len(row) < 2 {
			continue
		}
		if row[0] == "password" {
			break
		}
		input := row[1]
		// decode the key from the first argument
		inputNoSpaces := strings.Replace(input, " ", "", -1)
		inputNoSpacesUpper := strings.ToUpper(inputNoSpaces)
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(inputNoSpacesUpper)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		// generate a one-time password using the time at 30-second intervals

		pwd := oneTimePassword(key, toBytes(epochSeconds/30))
		text += fmt.Sprintf("%s: %06d \n", row[0], pwd)
	}
	fmt.Printf("%s", text)
	fmt.Printf("剩余有效期: %ds", secondsRemaining)
	return nil
}
func Encrypt(c *cli.Context) error {
	plaintext := c.String("text")
	res, _ := aes.NewAes([]byte(aesKey)).WithMode(&mode.ECBMode{}).Encrypt(plaintext)
	fmt.Printf("%s\n", res)
	return nil
}

func Decrypt(c *cli.Context) error {
	csv, err := csvx.NewCSV(file, ',', "\n")
	if err != nil {
		return err
	}
	defer func() {
		_ = csv.Close()
	}()
	key := c.String("key")
	isPassword := false
	for row, err := csv.ReadLine(); err == nil; row, err = csv.ReadLine() {
		if len(row) < 2 {
			continue
		}
		if row[0] == "password" {
			isPassword = true
			continue
		}

		if !isPassword || (key != row[0] && key != "all") {
			continue
		}
		res, _ := aes.NewAes([]byte(aesKey)).WithMode(&mode.ECBMode{}).Decrypt(row[1])
		fmt.Printf("%s: %s\n", row[0], res)
	}
	return nil
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}
