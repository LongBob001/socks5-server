package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

// 定义几个常量，代表对应的状态码
const socks5Ver = 0x05
const cmdBind = 0x01
const atypIPV4 = 0x01
const atypeHOST = 0x03
const atypeIPV6 = 0x04

func main() {
	//侦听端口，返回一个server
	server, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		panic(err)
	}
	for {
		//接收一个请求，接收成功返回一个连接client
		client, err := server.Accept()
		if err != nil {
			log.Printf("accept failed %v", err)
			continue
		}
		//处理该连接，go可以理解为启动一个子线程来处理连接，但实际上比子线程开销更小
		go process(client)
	}
}

func process(conn net.Conn) {
	defer conn.Close()              //关闭连接，使得连接和生命周期和函数的生命周期一致
	reader := bufio.NewReader(conn) //基于该连接创建一个只读的流
	//调用auth函数
	err := auth(reader, conn)
	if err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return
	}
	//调用connect函数
	err = connect(reader, conn)
	if err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return
	}
}

func auth(reader *bufio.Reader, conn net.Conn) (err error) {
	//前两个字段都是1个字节，用readbyte读取一个字节即可
	ver, err := reader.ReadByte()
	if err != nil { //出现错误直接return，此时调用auth的process也会return结束
		return fmt.Errorf("read ver failed:%w", err)
	}
	if ver != socks5Ver {
		return fmt.Errorf("not supported ver:%v", ver)
	}
	//同样只读取一个字节
	methodSize, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read methodSize failed:%w", err)
	}
	//第三个字段多个字节，创建一个method缓冲区然后readfull读满
	method := make([]byte, methodSize)
	_, err = io.ReadFull(reader, method)
	if err != nil {
		return fmt.Errorf("read method failed:%w", err)
	}
	//此时三个字段都读完了
	//log.Println("ver", ver, "method", method)
	//代理服务器要返回给浏览器一个报文，告诉浏览器ver和认证方式，这里0x00表示不需要认证
	_, err = conn.Write([]byte{socks5Ver, 0x00})
	if err != nil {
		return fmt.Errorf("write failed:%w", err)
	}
	return nil
}

func connect(reader *bufio.Reader, conn net.Conn) (err error) {
	//这里不再采用逐个字节读取的方式，采用创建4字节的缓冲区直接读取前四个字段
	buf := make([]byte, 4)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return fmt.Errorf("read header failed:%w", err)
	}
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	//验证合法性
	if ver != socks5Ver {
		return fmt.Errorf("not supported ver:%w", ver)
	}
	if cmd != cmdBind {
		return fmt.Errorf("not supported cmd:%w", ver)
	}
	//开始读取第5个字段，不定量长度
	addr := ""
	switch atyp {
	case atypIPV4:
		//IPv4正好也是4个字节，所以还是用上面的4字节缓冲区填充
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return fmt.Errorf("read atyp failed:%w", err)
		}
		addr = fmt.Sprintf("%d,%d,%d,%d", buf[0], buf[1], buf[2], buf[3])
	case atypeHOST:
		//HOST还是逐个字节读
		hostSize, err := reader.ReadByte()
		if err != nil {
			return fmt.Errorf("read hostSize failed:%w", err)
		}
		//创建对应长度的一个字符串
		host := make([]byte, hostSize)
		//填充字符串
		_, err = io.ReadFull(reader, host)
		if err != nil {
			return fmt.Errorf("read host failed:%w", err)
		}
		//强转为字符串
		addr = string(host)
	case atypeIPV6:
		return errors.New("IPv6:not supported yet")
	default:
		return errors.New("invalid atyp")
	}
	//最后一个字段端口号2字节，这里复用之前的4字节缓冲区，用切片截取前两个字节，变成2字节缓冲区
	_, err = io.ReadFull(reader, buf[:2])
	if err != nil {
		return fmt.Errorf("read port failed:%w", err)
	}
	//利用binary函数的大端字节序解析出整型数字
	port := binary.BigEndian.Uint16(buf[:2])
	//net.dial函数，利用tcp给目的IP和端口建立TCP连接
	dest, err := net.Dial("tcp", fmt.Sprintf("%v:%v", addr, port))
	if err != nil {
		return fmt.Errorf("dial dst failed:%w", err)
	}
	//函数结束时关闭连接
	defer dest.Close()
	//输出目的地址和端口号
	log.Println("dial", addr, port)

	//接受浏览器请求后要回复报文，根据回复报文字段的字节特征，一个字节1个值
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("write failed:%w", err)
	}
	//go routine启动是不耗时的，会瞬间跳转到return结束连接，所以这里用context函数，保证只有当任意一方copy失败，即cancel了，此时才终止连接
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = io.Copy(dest, reader) //从浏览器copy到服务器
		cancel()                     //copy失败的时候调用cancel函数
	}()
	go func() {
		_, _ = io.Copy(conn, dest) //从服务器copy到浏览器
		cancel()
	}()
	//当context函数完成后，即cancel函数被调用时，关闭连接
	<-ctx.Done()
	return nil
}
