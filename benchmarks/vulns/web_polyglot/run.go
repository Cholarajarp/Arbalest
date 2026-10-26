package tools

import "os/exec"

func runTask(task string) {
	cmd := exec.Command("sh", "-c", "run "+task)
	_ = cmd
}
