package httpsigtests

import (
	"os/exec"
)

func init() {
	cmd := exec.Command("npm", "install")
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}
