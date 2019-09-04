package util

var (
	_id = 0
)

func NextID() int {
	_id += 1
	return _id
}
