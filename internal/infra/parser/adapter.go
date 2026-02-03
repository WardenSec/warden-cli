package parser

import (
	pg_query "github.com/pganalyze/pg_query_go/v5"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(sql string) (interface{}, error) {
	result, err := pg_query.Parse(sql)
	if err != nil {
		return nil, err
	}
	return result, nil
}
