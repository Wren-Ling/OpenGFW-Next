package ruleset

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/expr-lang/expr/builtin"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
	"github.com/apernet/OpenGFW/ruleset/builtins"
)

// ExprRule is the external representation of an expression rule.
type ExprRule struct {
	Name     string        `yaml:"name"`
	Action   string        `yaml:"action"`
	Log      bool          `yaml:"log"`
	Severity string        `yaml:"severity"`
	Modifier ModifierEntry `yaml:"modifier"`
	Expr     string        `yaml:"expr"`
}

type ModifierEntry struct {
	Name string                 `yaml:"name"`
	Args map[string]interface{} `yaml:"args"`
}

func ExprRulesFromYAML(file string) ([]ExprRule, error) {
	bs, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var rules []ExprRule
	err = yaml.Unmarshal(bs, &rules)
	return rules, err
}

// compiledExprRule is the internal, compiled representation of an expression rule.
type compiledExprRule struct {
	Name        string
	Action      *Action // fallthrough if nil
	Log         bool
	Severity    string
	ModInstance modifier.Instance
	Program     *vm.Program
}

var _ Ruleset = (*exprRuleset)(nil)

type exprRuleset struct {
	Rules  []compiledExprRule
	Ans    []analyzer.Analyzer
	Logger Logger
}

func (r *exprRuleset) Analyzers(info StreamInfo) []analyzer.Analyzer {
	return r.Ans
}

func (r *exprRuleset) Match(info StreamInfo) MatchResult {
	env := streamInfoToExprEnv(info)
	for _, rule := range r.Rules {
		v, err := vm.Run(rule.Program, env)
		if err != nil {
			// Log the error and continue to the next rule.
			r.Logger.MatchError(info, rule.Name, err)
			continue
		}
		if vBool, ok := v.(bool); ok && vBool {
			if rule.Log {
				r.Logger.Log(info, rule.Name, MatchMetadata{Severity: rule.Severity})
			}
			if rule.Action != nil {
				return MatchResult{
					Action:      *rule.Action,
					ModInstance: rule.ModInstance,
				}
			}
		}
	}
	// No match
	return MatchResult{
		Action: ActionMaybe,
	}
}

// CompileExprRules compiles a list of expression rules into a ruleset.
// It returns an error if any of the rules are invalid, or if any of the analyzers
// used by the rules are unknown (not provided in the analyzer list).
func CompileExprRules(rules []ExprRule, ans []analyzer.Analyzer, mods []modifier.Modifier, config *BuiltinConfig) (Ruleset, error) {
	var compiledRules []compiledExprRule
	fullAnMap := analyzersToMap(ans)
	fullModMap := modifiersToMap(mods)
	depAnMap := make(map[string]analyzer.Analyzer)
	funcMap := buildFunctionMap(config)
	// Compile all rules and build a map of analyzers that are used by the rules.
	for _, rule := range rules {
		if rule.Action == "" && !rule.Log {
			return nil, fmt.Errorf("rule %q must have at least one of action or log", rule.Name)
		}
		severity, err := normalizeSeverity(rule.Severity)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid severity: %w", rule.Name, err)
		}
		var action *Action
		if rule.Action != "" {
			a, ok := actionStringToAction(rule.Action)
			if !ok {
				return nil, fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
			}
			action = &a
		}
		visitor := &idVisitor{Variables: make(map[string]bool), Identifiers: make(map[string]bool)}
		patcher := &idPatcher{FuncMap: funcMap}
		program, err := expr.Compile(rule.Expr,
			func(c *conf.Config) {
				c.Strict = false
				c.Expect = reflect.Bool
				c.Visitors = append(c.Visitors, visitor, patcher)
				for name, f := range funcMap {
					c.Functions[name] = &builtin.Function{
						Name:  name,
						Func:  f.Func,
						Types: f.Types,
					}
				}
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid expression: %w", rule.Name, err)
		}
		if patcher.Err != nil {
			return nil, fmt.Errorf("rule %q failed to patch expression: %w", rule.Name, patcher.Err)
		}
		for name := range visitor.Identifiers {
			// Skip built-in analyzers & user-defined variables
			if isBuiltInAnalyzer(name) || visitor.Variables[name] {
				continue
			}
			if _, ok := builtin.Index[name]; ok {
				continue
			}
			if f, ok := funcMap[name]; ok {
				// Built-in function, initialize if necessary
				if f.InitFunc != nil {
					if err := f.InitFunc(); err != nil {
						return nil, fmt.Errorf("rule %q failed to initialize function %q: %w", rule.Name, name, err)
					}
				}
			} else if a, ok := fullAnMap[name]; ok {
				// Analyzer, add to dependency map
				depAnMap[name] = a
			} else {
				return nil, fmt.Errorf("rule %q uses unknown analyzer or identifier %q", rule.Name, name)
			}
		}
		cr := compiledExprRule{
			Name:     rule.Name,
			Action:   action,
			Log:      rule.Log,
			Severity: severity,
			Program:  program,
		}
		if action != nil && *action == ActionModify {
			mod, ok := fullModMap[rule.Modifier.Name]
			if !ok {
				return nil, fmt.Errorf("rule %q uses unknown modifier %q", rule.Name, rule.Modifier.Name)
			}
			modInst, err := mod.New(rule.Modifier.Args)
			if err != nil {
				return nil, fmt.Errorf("rule %q failed to create modifier instance: %w", rule.Name, err)
			}
			cr.ModInstance = modInst
		}
		compiledRules = append(compiledRules, cr)
	}
	// Convert the analyzer map to a list.
	var depAns []analyzer.Analyzer
	for _, a := range depAnMap {
		depAns = append(depAns, a)
	}
	return &exprRuleset{
		Rules:  compiledRules,
		Ans:    depAns,
		Logger: config.Logger,
	}, nil
}

func normalizeSeverity(severity string) (string, error) {
	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity == "" {
		return "info", nil
	}
	switch severity {
	case "debug", "info", "low", "medium", "high", "critical":
		return severity, nil
	default:
		return "", fmt.Errorf("must be one of debug, info, low, medium, high, critical")
	}
}

func streamInfoToExprEnv(info StreamInfo) map[string]interface{} {
	meta := info.Meta
	if meta == nil {
		meta = map[string]string{}
	}
	m := map[string]interface{}{
		"id":    info.ID,
		"proto": info.Protocol.String(),
		"ip": map[string]string{
			"src": info.SrcIP.String(),
			"dst": info.DstIP.String(),
		},
		"port": map[string]uint16{
			"src": info.SrcPort,
			"dst": info.DstPort,
		},
		"meta": meta,
	}
	for anName, anProps := range info.Props {
		if len(anProps) != 0 {
			// Ignore analyzers with empty properties
			m[anName] = anProps
		}
	}
	return m
}

func isBuiltInAnalyzer(name string) bool {
	switch name {
	case "id", "proto", "ip", "port", "meta":
		return true
	default:
		return false
	}
}

func actionStringToAction(action string) (Action, bool) {
	switch strings.ToLower(action) {
	case "allow":
		return ActionAllow, true
	case "block":
		return ActionBlock, true
	case "drop":
		return ActionDrop, true
	case "modify":
		return ActionModify, true
	default:
		return ActionMaybe, false
	}
}

// analyzersToMap converts a list of analyzers to a map of name -> analyzer.
// This is for easier lookup when compiling rules.
func analyzersToMap(ans []analyzer.Analyzer) map[string]analyzer.Analyzer {
	anMap := make(map[string]analyzer.Analyzer)
	for _, a := range ans {
		anMap[a.Name()] = a
	}
	return anMap
}

// modifiersToMap converts a list of modifiers to a map of name -> modifier.
// This is for easier lookup when compiling rules.
func modifiersToMap(mods []modifier.Modifier) map[string]modifier.Modifier {
	modMap := make(map[string]modifier.Modifier)
	for _, m := range mods {
		modMap[m.Name()] = m
	}
	return modMap
}

// idVisitor is a visitor that collects all identifiers in an expression.
// This is for determining which analyzers are used by the expression.
type idVisitor struct {
	Variables   map[string]bool
	Identifiers map[string]bool
}

func (v *idVisitor) Visit(node *ast.Node) {
	if varNode, ok := (*node).(*ast.VariableDeclaratorNode); ok {
		v.Variables[varNode.Name] = true
	} else if idNode, ok := (*node).(*ast.IdentifierNode); ok {
		v.Identifiers[idNode.Value] = true
	}
}

// idPatcher patches the AST during expr compilation, replacing certain values with
// their internal representations for better runtime performance.
type idPatcher struct {
	FuncMap map[string]*Function
	Err     error
}

func (p *idPatcher) Visit(node *ast.Node) {
	switch (*node).(type) {
	case *ast.CallNode:
		callNode := (*node).(*ast.CallNode)
		if callNode.Callee == nil {
			// Ignore invalid call nodes
			return
		}
		if f, ok := p.FuncMap[callNode.Callee.String()]; ok {
			if f.PatchFunc != nil {
				if err := f.PatchFunc(&callNode.Arguments); err != nil {
					p.Err = err
					return
				}
			}
		}
	}
}

type Function struct {
	InitFunc  func() error
	PatchFunc func(args *[]ast.Node) error
	Func      func(params ...any) (any, error)
	Types     []reflect.Type
}

func buildFunctionMap(config *BuiltinConfig) map[string]*Function {
	fingerprints := newFingerprintMatchers(config.Fingerprints)
	domainKeywords := newDomainKeywordMatchers(config.DomainKeywords)
	return map[string]*Function{
		"geoip": {
			InitFunc:  config.GeoMatcher.LoadGeoIP,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return config.GeoMatcher.MatchGeoIp(params[0].(string), params[1].(string)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoIp)},
		},
		"geosite": {
			InitFunc:  config.GeoMatcher.LoadGeoSite,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return config.GeoMatcher.MatchGeoSite(params[0].(string), params[1].(string)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoSite)},
		},
		"cidr": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				cidrStringNode, ok := (*args)[1].(*ast.StringNode)
				if !ok {
					return fmt.Errorf("cidr: invalid argument type")
				}
				cidr, err := builtins.CompileCIDR(cidrStringNode.Value)
				if err != nil {
					return err
				}
				(*args)[1] = &ast.ConstantNode{Value: cidr}
				return nil
			},
			Func: func(params ...any) (any, error) {
				return builtins.MatchCIDR(params[0].(string), params[1].(*net.IPNet)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(builtins.MatchCIDR)},
		},
		"lookup": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				var serverStr *ast.StringNode
				if len(*args) > 1 {
					// Has the optional server argument
					var ok bool
					serverStr, ok = (*args)[1].(*ast.StringNode)
					if !ok {
						return fmt.Errorf("lookup: invalid argument type")
					}
				}
				r := &net.Resolver{
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if serverStr != nil {
							address = serverStr.Value
						}
						return config.ProtectedDialContext(ctx, network, address)
					},
				}
				if len(*args) > 1 {
					(*args)[1] = &ast.ConstantNode{Value: r}
				} else {
					*args = append(*args, &ast.ConstantNode{Value: r})
				}
				return nil
			},
			Func: func(params ...any) (any, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				return params[1].(*net.Resolver).LookupHost(ctx, params[0].(string))
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(string, *net.Resolver) []string)(nil)),
			},
		},
		"suspicious_ja3": {
			InitFunc:  nil,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return fingerprints.matchJA3(params[0]), nil
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(any) bool)(nil)),
			},
		},
		"suspicious_quic_ja3": {
			InitFunc:  nil,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return fingerprints.matchQUICJA3(params[0]), nil
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(any) bool)(nil)),
			},
		},
		"suspicious_ja4": {
			InitFunc:  nil,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return fingerprints.matchJA4(params[0]), nil
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(any) bool)(nil)),
			},
		},
		"suspicious_quic_ja4": {
			InitFunc:  nil,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return fingerprints.matchQUICJA4(params[0]), nil
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(any) bool)(nil)),
			},
		},
		"domain_keyword": {
			InitFunc:  nil,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return domainKeywords.match(params[0], params[1]), nil
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(any, any) bool)(nil)),
			},
		},
	}
}

type fingerprintMatchers struct {
	ja3     map[string]FingerprintEntry
	ja4     map[string]FingerprintEntry
	quicJA3 map[string]FingerprintEntry
	quicJA4 map[string]FingerprintEntry
}

func newFingerprintMatchers(config FingerprintConfig) fingerprintMatchers {
	return fingerprintMatchers{
		ja3:     fingerprintEntriesToMap(config.JA3.Suspicious),
		ja4:     fingerprintEntriesToMap(config.JA4.Suspicious),
		quicJA3: fingerprintEntriesToMap(config.QUICJA3.Suspicious),
		quicJA4: fingerprintEntriesToMap(config.QUICJA4.Suspicious),
	}
}

func fingerprintEntriesToMap(entries []FingerprintEntry) map[string]FingerprintEntry {
	m := make(map[string]FingerprintEntry, len(entries))
	for _, entry := range entries {
		hash := normalizeFingerprintHash(entry.Hash)
		if hash == "" {
			continue
		}
		entry.Hash = hash
		m[hash] = entry
	}
	return m
}

func (m fingerprintMatchers) matchJA3(hash any) bool {
	_, ok := m.ja3[normalizeFingerprintHashValue(hash)]
	return ok
}

func (m fingerprintMatchers) matchQUICJA3(hash any) bool {
	_, ok := m.quicJA3[normalizeFingerprintHashValue(hash)]
	return ok
}

func (m fingerprintMatchers) matchJA4(hash any) bool {
	_, ok := m.ja4[normalizeFingerprintHashValue(hash)]
	return ok
}

func (m fingerprintMatchers) matchQUICJA4(hash any) bool {
	_, ok := m.quicJA4[normalizeFingerprintHashValue(hash)]
	return ok
}

func normalizeFingerprintHashValue(value any) string {
	hash, ok := value.(string)
	if !ok {
		return ""
	}
	return normalizeFingerprintHash(hash)
}

func normalizeFingerprintHash(hash string) string {
	return strings.ToLower(strings.TrimSpace(hash))
}

type domainKeywordMatchers map[string][]string

func newDomainKeywordMatchers(config DomainKeywordConfig) domainKeywordMatchers {
	matchers := make(domainKeywordMatchers, len(config))
	for name, keywords := range config {
		name = normalizeDomainKeywordName(name)
		if name == "" {
			continue
		}
		for _, keyword := range keywords {
			keyword = normalizeDomainKeyword(keyword)
			if keyword == "" {
				continue
			}
			matchers[name] = append(matchers[name], keyword)
		}
	}
	return matchers
}

func (m domainKeywordMatchers) match(value any, list any) bool {
	valueString, ok := value.(string)
	if !ok {
		return false
	}
	listString, ok := list.(string)
	if !ok {
		return false
	}
	valueString = normalizeDomainKeyword(valueString)
	if valueString == "" {
		return false
	}
	for _, keyword := range m[normalizeDomainKeywordName(listString)] {
		if strings.Contains(valueString, keyword) {
			return true
		}
	}
	return false
}

func normalizeDomainKeywordName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeDomainKeyword(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
}
