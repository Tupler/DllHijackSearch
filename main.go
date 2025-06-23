package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	peparser "github.com/saferwall/pe"
)

func isSignatureValid(filePath string) bool {
	// PowerShell 脚本：获取签名状态
	script := fmt.Sprintf(`(Get-AuthenticodeSignature '%s').Status -eq 'Valid'`, filePath)

	cmd := exec.Command("powershell", "-Command", script)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return false
	}

	result := out.String()
	return result == "True\n"
}

func CheckUnknownDll(dllname string) bool {
	if _, err := os.Stat("c:\\windows\\" + dllname); os.IsNotExist(err) {
		if _, err = os.Stat("c:\\windows\\system32\\" + dllname); os.IsNotExist(err) {
			if strings.Contains(dllname, "api-ms-win") || strings.Contains(dllname, "MSVC") || strings.Contains(dllname, "ATL") {
				return true
			}

			return false //不存在
		} else {
			return true //存在！
		}
	} else {
		return true
	}
}

func CheckImport(path string) []string {
	pe, err := peparser.New(path, &peparser.Options{})
	check(err)
	err = pe.Parse()
	check(err)
	importCount := len(pe.Imports)
	ImportNames := make([]string, 0)
	for i := 0; i < importCount; i++ {
		if ApisetFlag && strings.Contains(pe.Imports[i].Name, "api-ms-win") {
			return []string{}
		}
		if !CheckUnknownDll(pe.Imports[i].Name) {
			ImportNames = append(ImportNames, pe.Imports[i].Name)
		}
	}
	return ImportNames
}

func visit(path string, f os.DirEntry, err error) error {
	if err != nil {
		fmt.Println(err) // 如果发生错误，输出错误信息并继续
		return err
	}

	//fmt.Println(path)
	// 如果是目录，则递归遍历
	if f.IsDir() && !strings.Contains(f.Name(), "$") {

		subEntries, err := os.ReadDir(path)
		//无法读取目录 ->可能原因
		if err != nil {
			fmt.Println("无法读取目录 Error->", err)
		}
		//循环递归子目录文件
		for _, subEntry := range subEntries {
			subPath := filepath.Join(path, subEntry.Name())
			//递归
			err := visit(subPath, subEntry, nil)
			if err != nil {
				return err
			}
		}
	} else {
		//判断后缀是否是.exe
		if path[len(path)-4:] == ".exe" {
			if SignVaildFlag && isSignatureValid(path) == false {
				return nil
			}
			Names := CheckImport(path)
			if len(Names) != 0 {
				fmt.Println("可劫持EXE:", path)
				fmt.Println("dll为:", Names)
			}
		}

	}
	return nil

}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

var Path string
var ApisetFlag bool
var SignVaildFlag bool

func init() {
	flag.StringVar(&Path, "p", "C:\\", "设置一个要搜索的目录,默认C盘根目录")
	flag.BoolVar(&ApisetFlag, "a", true, "设置是否排除apiset的DLL(true即不显示存在api-xxxx的导入表的可劫持文件)")
	flag.BoolVar(&SignVaildFlag, "s", true, "设置是否排除签名不正确的exe")
	flag.Parse()
}
func main() {
	err := filepath.WalkDir(Path, visit)
	if err != nil {
		fmt.Println(err)
		return
	}
}
