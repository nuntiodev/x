package emailx

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
)

type Email interface {
	SendEmail(to, subject, templatePath string, data any) error
}

type defaultEmail struct {
	auth smtp.Auth
	from string
	port string
	host string
}

func New(smtpFrom, smtpHost, smtpPort string, auth smtp.Auth) (Email, error) {
	return &defaultEmail{
		auth: auth,
		from: smtpFrom,
		host: smtpHost,
		port: smtpPort,
	}, nil
}

func (e *defaultEmail) SendEmail(to, subject, templatePath string, data any) error {
	if templatePath == "" {
		// you either have to specify a template or valid data
		if data == nil || data == "" {
			return errors.New("data must contain some information")
		}
		// convert to bytes
		var buffer bytes.Buffer        // Stand-in for a network connection
		enc := gob.NewEncoder(&buffer) // Will write to network.
		// Encode (send) the value.
		err := enc.Encode(data)
		if err != nil {
			return err
		}
		// message with no html template.
		message := buffer.Bytes()
		// sending email.
		if err := smtp.SendMail(e.host+":"+e.port, e.auth, e.from, []string{to}, message); err != nil {
			return err
		}
		return nil
	}
	// message with template
	t, _ := template.ParseFiles(templatePath)
	var body bytes.Buffer
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: %s \nFrom: %s \n%s\n\n", subject, e.from, mimeHeaders)))
	if err := t.Execute(&body, data); err != nil {
		return err
	}

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         e.host,
	}
	conn, err := tls.Dial("tcp", e.host+":"+e.port, tlsconfig)
	if err != nil {
		fmt.Println(e.host + ":" + e.port)
		return err
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		return err
	}
	if err = c.Auth(e.auth); err != nil {
		return err
	}
	if err = c.Mail(e.from); err != nil {
		return err
	}
	if err = c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(body.Bytes())
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}
	c.Quit()
	return nil
}
