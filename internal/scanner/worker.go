package scanner

// scanJob là một đơn vị công việc được worker xử lý.
type scanJob struct {
	path string
}

// scanReply là phản hồi từ worker về goroutine tổng hợp.
type scanReply struct {
	result ScanResult
	err    error
}
