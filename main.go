package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/weblazy/easy/utils/csvx"
)

func main() {
	// 打印Banner
	projectName := "2FA"
	// 配置cli参数
	app := cli.NewApp()
	app.Name = projectName
	app.Usage = projectName
	app.Version = "1.0.0"

	// 指定命令运行的函数
	app.Commands = []*cli.Command{
		Cmd,
	}

	// 启动cli
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%#v\n", err)
	}
}

var Cmd = &cli.Command{
	Name:    "list",
	Aliases: []string{"list"},
	Usage:   "list -c FA_PATH",
	Action:  Run,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "env_conf",
			Aliases: []string{"c"},
			Usage:   "env_conf",
			Value:   "FA_PATH",
		},
	},
}

// all []byte in this program are treated as Big Endian
func Run(c *cli.Context) error {
	env := c.String("c")
	file := os.Getenv(env)
	csv, err := csvx.NewCSV(file, ',', "\n")
	if err != nil {
		return err
	}
	defer func() {
		_ = csv.Close()
	}()
	for row, err := csv.ReadLine(); err == nil; row, err = csv.ReadLine() {
		if len(row) < 2 {
			continue
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
		epochSeconds := time.Now().Unix()
		pwd := oneTimePassword(key, toBytes(epochSeconds/30))

		secondsRemaining := 30 - (epochSeconds % 30)
		fmt.Printf("%s: %06d %ds remaining\n", row[0], pwd, secondsRemaining)
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
