package BetterSSH

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"strconv"
	"time"
)

// A Client implements an SSH client that supports running commands and scripts remotely.
type Client struct {
	client        *ssh.Client
	session       *ssh.Session
	stdin         io.WriteCloser
	stdout        io.Reader
	stdoutscanner *bufio.Scanner
}

func Connect(host string, port int, username string, password string) (*Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), config)
	if err != nil {
		return nil, err
	}

	var stdin io.WriteCloser
	var stdout io.Reader

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Error opening new Session")
	}

	stdin, err = session.StdinPipe()
	if err != nil {
		log.Fatal(err.Error())
	}

	stdout, err = session.StdoutPipe()
	if err != nil {
		fmt.Println(err.Error())
	}

	if err != nil {
		log.Fatal(err.Error())
	}

	session.Shell()
	return &Client{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
	}, nil
}

func (c *Client) Execute(command string) (string, int) {
	c.stdin.Write([]byte("echo \x01\x08\x07\n"))
	log.Println("Execute Command")
	c.stdin.Write([]byte(command + "\n"))
	c.stdin.Write([]byte("oldret=$(echo $?) && echo \x01\x08\x07 && echo $oldret\n"))
	c.stdin.Write([]byte("echo \x01\x08\x07\n"))
	log.Println("Reading...")
	fullBuffer := []byte{0, 0, 0, 0, 0, 0}
	startSet := false
	start := 0
	commendEnd := 0
	commendEndSet := false
	commendHasNoOutput := false
	for {
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c.stdout, buf); err != nil {
			log.Fatal(err)
		}
		fullBuffer = append(fullBuffer, buf...)
		//fmt.Printf("%v\n\n", fullBuffer)
		if res := bytes.Compare(fullBuffer[len(fullBuffer)-7:], []byte{1, 8, 7, 10, 1, 8, 7}); res == 0 {
			commendHasNoOutput = true
		}
		if res := bytes.Compare(fullBuffer[len(fullBuffer)-3:], []byte{1, 8, 7}); res == 0 {
			if startSet == true && commendEndSet == false {
				commendEnd = len(fullBuffer) - 4
				commendEndSet = true
			} else if commendEndSet == true {
				returnCode, _ := strconv.Atoi(string(fullBuffer[commendEnd+5 : len(fullBuffer)-4]))
				if commendHasNoOutput == false {
					//return fullBuffer, fullBuffer[start:commendEnd], fullBuffer[commendEnd+5 : len(fullBuffer)-4]
					return string(fullBuffer[start:commendEnd]), returnCode
				} else {
					//return fullBuffer, nil, fullBuffer[commendEnd+5 : len(fullBuffer)-4]
					return "", returnCode
				}
			} else {
				start = len(fullBuffer) + 1
				startSet = true
			}
		}
	}
}

func (c *Client) ExecuteAsSudo(command string, password string) (string, int) {
	sudoCommend := "echo \"" + password + "\" | sudo -S " + command
	return c.Execute(sudoCommend)
}

func (c *Client) Disconnect() error {
	err := c.session.Close()
	if err != nil {
		return err
	}
	return c.client.Close()
}
