package main

import (
	"flag"
	"fmt"
	peparser "github.com/saferwall/pe"
	"log"
	"os"
	"path/filepath"
	"strings"
)

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

func init() {
	flag.StringVar(&Path, "p", "C:\\", "设置一个要搜索的目录,默认C盘根目录")
	flag.Parse()
}
func main() {
	err := filepath.WalkDir(Path, visit)
	if err != nil {
		fmt.Println(err)
		return
	}
}
