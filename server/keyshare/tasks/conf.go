package tasks

import (
	"html/template"

	irma "github.com/BeardOfDoom/pq-irmago"
	"github.com/BeardOfDoom/pq-irmago/server"
	"github.com/BeardOfDoom/pq-irmago/server/keyshare"
	"github.com/sirupsen/logrus"
)

type Configuration struct {
	// Database configuration
	DBConnStr string `json:"db_str" mapstructure:"db_str"`

	// Configuration for deleting expired accounts
	ExpiryDelay int `json:"expiry_delay" mapstructure:"expiry_delay"`
	DeleteDelay int `json:"delete_delay" mapstructure:"delete_delay"`

	// Email sending configuration
	keyshare.EmailConfiguration `mapstructure:",squash"`

	DeleteExpiredAccountFiles    map[string]string `json:"delete_expired_account_files" mapstructure:"delete_expired_account_files"`
	DeleteExpiredAccountSubjects map[string]string `json:"delete_expired_account_subjects" mapstructure:"delete_expired_account_subjects"`
	deleteExpiredAccountTemplate map[string]*template.Template

	// Logging verbosity level: 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
	Verbose int `json:"verbose" mapstructure:"verbose"`
	// Don't log anything at all
	Quiet bool `json:"quiet" mapstructure:"quiet"`
	// Output structured log in JSON format
	LogJSON bool `json:"log_json" mapstructure:"log_json"`
	// Custom logger instance. If specified, Verbose, Quiet and LogJSON are ignored.
	Logger *logrus.Logger `json:"-"`
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) error {
	// Setup log
	if conf.Logger == nil {
		conf.Logger = server.NewLogger(conf.Verbose, conf.Quiet, conf.LogJSON)
	}
	server.Logger = conf.Logger
	irma.Logger = conf.Logger

	// Setup email templates
	if conf.EmailServer != "" {
		var err error
		conf.deleteExpiredAccountTemplate, err = keyshare.ParseEmailTemplates(
			conf.DeleteExpiredAccountFiles,
			conf.DeleteExpiredAccountSubjects,
			conf.DefaultLanguage,
		)
		if err != nil {
			return server.LogError(err)
		}
	}

	if err := conf.VerifyEmailServer(); err != nil {
		return server.LogError(err)
	}

	return nil
}
