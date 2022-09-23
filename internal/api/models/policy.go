package models

import "time"

type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	PolicyData  PolicyData `json:"policy_data"`
	SocketIDs   []string   `json:"socket_ids"`
}

type PolicyData struct {
	Action    []string  `json:"action" mapstructure:"action"`
	Condition Condition `json:"condition" mapstructure:"condition"`
}

type Condition struct {
	Who   ConditionWho   `json:"who,omitempty" mapstructure:"who"`
	Where ConditionWhere `json:"Where,omitempty" mapstructure:"where"`
	When  ConditionWhen  `json:"When,omitempty" mapstructure:"when"`
	What  ConditionWhat  `json:"What,omitempty" mapstructure:"what"`
}

type ConditionWho struct {
	Email  []string `json:"email,omitempty" mapstructure:"email"`
	Domain []string `json:"domain,omitempty" mapstructure:"domain"`
}

type ConditionWhere struct {
	AllowedIP []string `json:"allowed_ip,omitempty" mapstructure:"allowed_ip"`
	Country   []string `json:"country,omitempty" mapstructure:"country"`
}

type ConditionWhat struct{}

type ConditionWhen struct {
	After           *time.Time `json:"after,omitempty" mapstructure:"after"`
	Before          *time.Time `json:"before,omitempty" mapstructure:"before"`
	TimeOfDayAfter  string     `json:"time_of_day_after,omitempty" mapstructure:"time_of_day_after"`
	TimeOfDayBefore string     `json:"time_of_day_before,omitempty" mapstructure:"time_of_day_before"`
}
