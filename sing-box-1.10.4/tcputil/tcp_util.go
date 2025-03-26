package tcputil

import (
	"errors"
	"reflect"
	"unsafe"
)

//
// 内存池需要实现的接口
//
type MemPool interface {
	Alloc(size int) []byte
}


type SimpleMemPool struct {
	memPool     []byte
	memPoolSize int
	maxPackSize int
}


func NewSimpleMemPool(memPoolSize, maxPackSize int) (*SimpleMemPool, error) {
	if maxPackSize > memPoolSize {
		return nil, errors.New("maxPackSize > memPoolSize")
	}

	return &SimpleMemPool{
		memPool:     make([]byte, memPoolSize),
		memPoolSize: memPoolSize,
		maxPackSize: maxPackSize,
	}, nil
}


func (this *SimpleMemPool) Alloc(size int) (result []byte) {
	if size > this.maxPackSize {
		return nil
	}

	if len(this.memPool) < size {
		this.memPool = make([]byte, this.memPoolSize)
	}

	result = this.memPool[0:size]
	this.memPool = this.memPool[size:]

	return result
}

func getUint(buff []byte, pack int) int {
	var ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&buff)).Data)

	switch pack {
	case 1:
		return int(buff[0])
	case 2:
		return int(*(*uint16)(ptr))
	case 4:
		return int(*(*uint32)(ptr))
	case 8:
		return int(*(*uint64)(ptr))
	}

	return 0
}

func setUint(buff []byte, pack, value int) {
	var ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&buff)).Data)

	switch pack {
	case 1:
		buff[0] = byte(value)
	case 2:
		*(*uint16)(ptr) = uint16(value)
	case 4:
		*(*uint32)(ptr) = uint32(value)
	case 8:
		*(*uint64)(ptr) = uint64(value)
	}
}

func getUint16(target []byte) uint16 {
	return *(*uint16)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&target)).Data))
}

func setUint16(target []byte, value uint16) {
	*(*uint16)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&target)).Data)) = value
}

func getUint32(target []byte) uint32 {
	return *(*uint32)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&target)).Data))
}

func setUint32(target []byte, value uint32) {
	*(*uint32)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&target)).Data)) = value
}
