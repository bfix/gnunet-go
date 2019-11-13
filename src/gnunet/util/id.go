package util

var (
	_id = 0
)

// generate next unique identifier (unique in the running process/application)
func NextID() int {
	_id++
	return _id
}
