package emailx

import (
	"context"
	"testing"

	"github.com/nuntiodev/x/mockx/email_mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestSendEmail(t *testing.T) {
	zapLog, err := zap.NewDevelopment()
	assert.NoError(t, err)
	smtpPort, removeContainer, err := email_mock.NewEmailMock(context.Background(), zapLog, "emailx")
	email, err := New("dev@testing.io", "", "127.0.0.1", smtpPort)
	assert.NoError(t, err)
	assert.NoError(t, err)
	assert.NoError(t, email.SendEmail("info@softcorp.io", "test mailslurper", "", "Hello!"))
	assert.NoError(t, removeContainer())
}
