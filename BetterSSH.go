package BetterSSH

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"path/filepath"
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
	sftp          *sftp.Client
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

	err = session.Shell()
	if err != nil {
		return nil, err
	}
	return &Client{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		sftp:    nil,
	}, nil
}

func (c *Client) ConnectSFPT() error {
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return err
	}
	c.sftp = sftpClient
	return nil
}

func (c *Client) DisconnectSFPT() error {
	err := c.sftp.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Execute(command string) (string, int) {
	_, err := c.stdin.Write([]byte("echo \x01\x08\x07\n"))
	log.Println("Execute Command")
	_, err = c.stdin.Write([]byte(command + " 2>&1\n"))
	_, err = c.stdin.Write([]byte("oldret=$(echo $?) && echo \x01\x08\x07 && echo $oldret\n"))
	_, err = c.stdin.Write([]byte("echo \x01\x08\x07\n"))
	if err != nil {
		log.Fatal(err)
		return "", 1
	}
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
		fmt.Printf("%v\n\n", fullBuffer)
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
					if res := bytes.Compare(fullBuffer[commendEnd:commendEnd+1], []byte{10}); res == 0 {
						//With new line
						log.Println("With")
						return string(fullBuffer[start:commendEnd]), returnCode
					} else {
						//Without new line
						log.Println("Without")
						return string(fullBuffer[start : commendEnd+1]), returnCode
					}
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
	out, returnCode := c.Execute(sudoCommend)
	return out, returnCode
}

func (c *Client) Disconnect() error {
	err := c.session.Close()
	if err != nil {
		return err
	}
	return c.client.Close()
}

func (c *Client) CopyFile(srcPath string, dstPath string) error {
	if c.sftp == nil {
		return errors.New("Please first connect to the Fileserver")
	}
	// Open the source file
	absSrcPath, err := filepath.Abs(srcPath)
	srcFile, err := os.Open(absSrcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create the destination file
	dstFile, err := c.sftp.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// write to file
	if _, err := dstFile.ReadFrom(srcFile); err != nil {
		return err
	}
	return nil
}
