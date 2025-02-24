package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dave/jennifer/jen"
	. "github.com/dave/jennifer/jen"
	"github.com/davecgh/go-spew/spew"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	. "github.com/gagliardetto/utilz"
	"github.com/henrymbaldwin/solana-anchor-go/sighash"
	"golang.org/x/mod/modfile"
)

const generatedDir = "generated"

// TODO:
// - tests where type has field that is a complex enum (represented as an interface): assign a random concrete value from the possible enum variants.
// - when printing tree, check for len before accessing array indexes.

func main() {
	conf.Encoding = EncodingBorsh
	conf.TypeID = TypeIDAnchor

	filenames := FlagStringArray{}
	flag.Var(&filenames, "src", "Path to source; can use multiple times.")
	flag.StringVar(&conf.DstDir, "dst", generatedDir, "Destination folder")
	flag.StringVar(&conf.Package, "pkg", "", "Set package name to generate, default value is metadata.name of the source IDL.")
	flag.BoolVar(&conf.Debug, "debug", false, "debug mode")
	flag.BoolVar(&conf.RemoveAccountSuffix, "remove-account-suffix", false, "Remove \"Account\" suffix from accessors (if leads to duplication, e.g. \"SetFooAccountAccount\")")

	flag.StringVar((*string)(&conf.Encoding), "codec", string(EncodingBorsh), "Choose codec")
	flag.StringVar((*string)(&conf.TypeID), "type-id", string(TypeIDAnchor), "Choose typeID kind")
	flag.StringVar(&conf.ModPath, "mod", "", "Generate a go.mod file with the necessary dependencies, and this module")
	flag.Parse()

	if err := conf.Validate(); err != nil {
		panic(fmt.Errorf("error while validating config: %w", err))
	}

	var ts time.Time
	if GetConfig().Debug {
		ts = time.Unix(0, 0)
	} else {
		ts = time.Now()
	}
	if len(filenames) == 0 {
		Sfln(
			"[%s] No IDL files provided",
			Red(XMark),
		)
		os.Exit(1)
	}
	{
		exists, err := DirExists(GetConfig().DstDir)
		if err != nil {
			panic(err)
		}
		if !exists {
			MustCreateFolderIfNotExists(GetConfig().DstDir, os.ModePerm)
		}
	}

	callbacks := make([]func(), 0)
	defer func() {
		for _, cb := range callbacks {
			cb()
		}
	}()

	for _, idlFilepath := range filenames {
		Sfln(
			"[%s] Generating client from IDL: %s",
			Shakespeare("+"),
			Shakespeare(idlFilepath),
		)
		idlFile, err := os.Open(idlFilepath)
		if err != nil {
			panic(err)
		}

		dec := json.NewDecoder(idlFile)

		var idl IDL

		err = dec.Decode(&idl)
		if err != nil {
			panic(err)
		}
		{
			if idl.State != nil {
				Sfln(
					"%s idl.State is defined, but generator is not implemented yet.",
					OrangeBG("[?]"),
				)
			}
			//if len(idl.Events) > 0 {
			//	Sfln(
			//		"%s idl.Events is defined, but generator is not implemented yet.",
			//		OrangeBG("[?]"),
			//	)
			//}
			//if len(idl.Errors) > 0 {
			//	Sfln(
			//		"%s idl.Errors is defined, but generator is not implemented yet.",
			//		OrangeBG("[?]"),
			//	)
			//}
			//if len(idl.Constants) > 0 {
			//	Sfln(
			//		"%s idl.Constants is defined, but generator is not implemented yet.",
			//		OrangeBG("[?]"),
			//	)
			//}
		}

		// spew.Dump(idl)

		// Create subfolder for package for generated assets:
		packageAssetFolderName := sighash.ToRustSnakeCase(idl.Metadata.Name)
		var dstDirForFiles string
		if GetConfig().Debug {
			packageAssetFolderPath := path.Join(GetConfig().DstDir, packageAssetFolderName)
			MustCreateFolderIfNotExists(packageAssetFolderPath, os.ModePerm)
			// Create folder for assets generated during this run:
			thisRunAssetFolderName := ToLowerCamel(idl.Metadata.Name) + "_" + ts.Format(FilenameTimeFormat)
			thisRunAssetFolderPath := path.Join(packageAssetFolderPath, thisRunAssetFolderName)
			// Create a new assets folder inside the main assets folder:
			MustCreateFolderIfNotExists(thisRunAssetFolderPath, os.ModePerm)
			dstDirForFiles = thisRunAssetFolderPath
		} else {
			if GetConfig().DstDir == generatedDir {
				dstDirForFiles = filepath.Join(GetConfig().DstDir, packageAssetFolderName)
			} else {
				dstDirForFiles = GetConfig().DstDir
			}
		}
		MustCreateFolderIfNotExists(dstDirForFiles, os.ModePerm)

		files, err := GenerateClientFromProgramIDL(idl)
		if err != nil {
			panic(err)
		}

		{
			mdf := &modfile.File{}
			mdf.AddModuleStmt(GetConfig().ModPath)

			mdf.AddNewRequire("github.com/gagliardetto/solana-go", "v1.5.0", false)
			mdf.AddNewRequire("github.com/fragmetric-labs/solana-binary-go", "v0.8.0", false)
			mdf.AddNewRequire("github.com/gagliardetto/treeout", "v0.1.4", false)
			mdf.AddNewRequire("github.com/gagliardetto/gofuzz", "v1.2.2", false)
			mdf.AddNewRequire("github.com/stretchr/testify", "v1.6.1", false)
			mdf.AddNewRequire("github.com/davecgh/go-spew", "v1.1.1", false)
			mdf.Cleanup()

			//callbacks = append(callbacks, func() {
			//	Ln()
			//	Ln(Bold("Don't forget to import the necessary dependencies!"))
			//	Ln()
			//	for _, v := range mdf.Require {
			//		Sfln(
			//			"	go get %s@%s",
			//			v.Mod.Path,
			//			v.Mod.Version,
			//		)
			//	}
			//	Ln()
			//})

			if GetConfig().ModPath != "" {
				mfBytes, err := mdf.Format()
				if err != nil {
					panic(err)
				}
				gomodFilepath := filepath.Join(dstDirForFiles, "go.mod")
				Sfln(
					"[%s] %s",
					Lime(Checkmark),
					MustAbs(gomodFilepath),
				)
				// Write `go.mod` file:
				err = ioutil.WriteFile(gomodFilepath, mfBytes, 0666)
				if err != nil {
					panic(err)
				}
			}
		}

		for _, file := range files {
			// err := file.Render(os.Stdout)
			// if err != nil {
			// 	panic(err)
			// }

			file.File.HeaderComment("Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.")
			{
				// Save assets:
				assetFileName := file.Name + ".go"
				assetFilepath := path.Join(dstDirForFiles, assetFileName)

				// Create file:
				goFile, err := os.Create(assetFilepath)
				if err != nil {
					panic(err)
				}
				defer goFile.Close()

				// Write generated code file:
				Sfln(
					"[%s] %s",
					Lime(Checkmark),
					MustAbs(assetFilepath),
				)
				err = file.File.Render(goFile)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func FormatSighash(buf []byte) string {
	elems := make([]string, 0)
	for _, v := range buf {
		elems = append(elems, strconv.Itoa(int(v)))
	}

	return "[" + strings.Join(elems, ", ") + "]"
}

func GenerateClientFromProgramIDL(idl IDL) ([]*FileWrapper, error) {
	if idl.Address == "" {
		idl.Address = idl.Metadata.Address
	}

	if GetConfig().Package != "" {
		idl.Metadata.Name = GetConfig().Package
	}

	if err := idl.Validate(); err != nil {
		return nil, err
	}

	// configurable address map
	addresses := make(map[string]string)

	// map to store account addresses
	accountAddresses := make(map[string]string)

	files := make([]*FileWrapper, 0)
	{
		// Create and populate Go file that holds all the basic
		// elements of an instruction client:
		file, err := genProgramBoilerplate(idl)
		if err != nil {
			return nil, err
		}

		file.Add(Empty().Id(`
func DecodeInstructions(message *ag_solanago.Message) (instructions []*Instruction, err error) {
	for _, ins := range message.Instructions {
		var programID ag_solanago.PublicKey
		if programID, err = message.Program(ins.ProgramIDIndex); err != nil {
			return
		}
		if !programID.Equals(ProgramID) {
			continue
		}
		var accounts []*ag_solanago.AccountMeta
		if accounts, err = ins.ResolveInstructionAccounts(message); err != nil {
			return
		}
		var insDecoded *Instruction
		if insDecoded, err = decodeInstruction(accounts, ins.Data); err != nil {
			return
		}
		instructions = append(instructions, insDecoded)
	}
	return
}
`))

		files = append(files, &FileWrapper{
			Name: "instructions",
			File: file,
		})
	}
	{
		// register complex enums:
		for _, typ := range idl.Types {
			registerComplexEnums(&idl, typ)
		}
		for _, typ := range idl.Accounts {
			registerComplexEnums(&idl, typ)
		}
	}

	defs := make(map[string]IdlTypeDef)
	{
		file := NewGoFile(idl.Metadata.Name, true)
		// Declare types from IDL:
		for _, typ := range idl.Types {
			defs[typ.Name] = typ
			file.Add(genTypeDef(&idl, nil, IdlTypeDef{
				Name: typ.Name,
				Type: typ.Type,
			}))
		}
		files = append(files, &FileWrapper{
			Name: "types",
			File: file,
		})
	}

	{
		file := NewGoFile(idl.Metadata.Name, true)
		// Declare account layouts from IDL:
		for _, acc := range idl.Accounts {
			if _, ok := defs[acc.Name]; ok {
				file.Add(genTypeDef(&idl, acc.Discriminator, IdlTypeDef{
					Name: defs[acc.Name].Name + "Account",
					Type: defs[acc.Name].Type,
				}))
			} else {
				panic(`not implemented - only IDL from ("anchor": ">=0.30.0") is available`)
			}
		}
		files = append(files, &FileWrapper{
			Name: "accounts",
			File: file,
		})
	}

	{
		file := NewGoFile(idl.Metadata.Name, true)
		// Declare account layouts from IDL:
		for _, evt := range idl.Events {
			if _, ok := defs[evt.Name]; ok {
				eventDataTypeName := defs[evt.Name].Name + "EventData"
				file.Add(genTypeDef(&idl, evt.Discriminator, IdlTypeDef{
					Name: eventDataTypeName,
					Type: defs[evt.Name].Type,
				}))
				file.Add(Func().Params(Op("*").Id(eventDataTypeName)).Id("isEventData").Params().Block())
			} else {
				panic(`not implemented - only IDL from ("anchor": ">=0.30.0") is available`)
			}
		}

		file.Add(Empty().Var().Id("eventTypes").Op("=").Map(Index(Lit(8)).Byte()).Qual("reflect", "Type").Values(DictFunc(func(d Dict) {
			for _, evt := range idl.Events {
				if def, ok := defs[evt.Name]; ok {
					d[Id(def.Name+"EventDataDiscriminator")] = Id("reflect.TypeOf(" + def.Name + "EventData{})")
				}
			}
		})))

		file.Add(Empty().Var().Id("eventNames").Op("=").Map(Index(Lit(8)).Byte()).String().Values(DictFunc(func(d Dict) {
			for _, evt := range idl.Events {
				if def, ok := defs[evt.Name]; ok {
					d[Id(def.Name+"EventDataDiscriminator")] = Lit(def.Name)
				}
			}
		})))

		file.Add(Var().Defs(
			Id("_").Op("*").Qual("strings", "Builder").Op("=").Nil(),
			Id("_").Op("*").Qual("encoding/base64", "Encoding").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgBinary, "Decoder").Op("=").Nil(),
			Id("_").Op("*").Qual("fmt", "Formatter").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgSolanaGo, "PublicKey").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgSolanaGoRpc, "GetTransactionResult").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgSolanaGoRpcJsonrpc, "RPCError").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgBase58, "Alphabet").Op("=").Nil(),
		))
		file.Add(Empty().Id(`
type Event struct {
	Name string
	Data EventData
}	

type EventData interface {
	UnmarshalWithDecoder(decoder *ag_binary.Decoder) error
	isEventData()
}

const eventLogPrefix = "Program data: "

func DecodeEvents(txData *ag_rpc.GetTransactionResult, targetProgramId ag_solanago.PublicKey, getAddressTables func(altAddresses []ag_solanago.PublicKey) (tables map[ag_solanago.PublicKey]ag_solanago.PublicKeySlice, err error)) (evts []*Event, err error) {
	var tx *ag_solanago.Transaction
	if tx, err = txData.Transaction.GetTransaction(); err != nil {
		return
	}

	altAddresses := make([]ag_solanago.PublicKey, len(tx.Message.AddressTableLookups))
	for i, alt := range tx.Message.AddressTableLookups {
		altAddresses[i] = alt.AccountKey
	}
	if len(altAddresses) > 0 {
		var tables map[ag_solanago.PublicKey]ag_solanago.PublicKeySlice
		if tables, err = getAddressTables(altAddresses); err != nil {
			return
		}
		tx.Message.SetAddressTables(tables)
		if err = tx.Message.ResolveLookups(); err != nil {
			return
		}
	}

	var base64Binaries [][]byte
	logMessageEventBinaries, err := decodeEventsFromLogMessage(txData.Meta.LogMessages)
	if err != nil {
		return
	}

	emitedCPIEventBinaries, err := decodeEventsFromEmitCPI(txData.Meta.InnerInstructions, tx.Message.AccountKeys, targetProgramId)
	if err != nil {
		return
	}

	base64Binaries = append(base64Binaries, logMessageEventBinaries...)
	base64Binaries = append(base64Binaries, emitedCPIEventBinaries...)
	evts, err = parseEvents(base64Binaries)
	return
}

func decodeEventsFromLogMessage(logMessages []string) (eventBinaries [][]byte, err error) {
	for _, log := range logMessages {
		if strings.HasPrefix(log, eventLogPrefix) {
			eventBase64 := log[len(eventLogPrefix):]

			var eventBinary []byte
			if eventBinary, err = base64.StdEncoding.DecodeString(eventBase64); err != nil {
				err = fmt.Errorf("failed to decode logMessage event: %s", eventBase64)
				return
			}
			eventBinaries = append(eventBinaries, eventBinary)
		}
	}
	return
}

func decodeEventsFromEmitCPI(InnerInstructions []ag_rpc.InnerInstruction, accountKeys ag_solanago.PublicKeySlice, targetProgramId ag_solanago.PublicKey) (eventBinaries [][]byte, err error) {
	for _, parsedIx := range InnerInstructions {
		for _, ix := range parsedIx.Instructions {
			if accountKeys[ix.ProgramIDIndex] != targetProgramId {
				continue
			}

			var ixData []byte
			if ixData, err = ag_base58.Decode(ix.Data.String()); err != nil {
				return
			}
			eventBase64 := base64.StdEncoding.EncodeToString(ixData[8:])
			var eventBinary []byte
			if eventBinary, err = base64.StdEncoding.DecodeString(eventBase64); err != nil {
				return
			}
			eventBinaries = append(eventBinaries, eventBinary)
		}
	}
	return
}

func parseEvents(base64Binaries [][]byte) (evts []*Event, err error) {
	decoder := ag_binary.NewDecoderWithEncoding(nil, ag_binary.EncodingBorsh)

	for _, eventBinary := range base64Binaries {
		eventDiscriminator := ag_binary.TypeID(eventBinary[:8])
		if eventType, ok := eventTypes[eventDiscriminator]; ok {
			eventData := reflect.New(eventType).Interface().(EventData)
			decoder.Reset(eventBinary)
			if err = eventData.UnmarshalWithDecoder(decoder); err != nil {
				err = fmt.Errorf("failed to unmarshal event %s: %w", eventType.String(), err)
				return
			}
			evts = append(evts, &Event{
				Name: eventNames[eventDiscriminator],
				Data: eventData,
			})
		}
	}
	return
}
`))

		files = append(files, &FileWrapper{
			Name: "events",
			File: file,
		})
	}

	{
		// define custom errors
		file := NewGoFile(idl.Metadata.Name, true)

		// to generate import statements
		file.Add(Var().Defs(
			Id("_").Op("*").Qual("encoding/json", "Encoder").Op("=").Nil(),
			Id("_").Op("*").Qual("github.com/gagliardetto/solana-go/rpc/jsonrpc", "RPCError").Op("=").Nil(),
			Id("_").Qual("fmt", "Formatter").Op("=").Nil(),
			Id("_").Op("=").Qual("errors", "ErrUnsupported"),
		))

		file.Add(Var().DefsFunc(func(group *Group) {
			errDict := Dict{}
			for _, errDef := range idl.Errors {
				name := "Err" + ToCamel(errDef.Name)
				group.Add(Id(name).Op("=").Op("&").Id("customErrorDef").Values(Dict{
					Id("code"): Lit(errDef.Code),
					Id("name"): Lit(errDef.Name),
					Id("msg"):  Lit(errDef.Msg),
				}))
				errDict[Lit(errDef.Code)] = Id(name)
			}
			group.Add(Id("Errors").Op("=").Map(Int()).Id("CustomError").Values(errDict))
		}))

		file.Add(Empty().Id(`
type CustomError interface {
	Code() int
	Name() string
	Error() string
}

type customErrorDef struct {
	code int
	name string
	msg  string
}

func (e *customErrorDef) Code() int {
	return e.code
}

func (e *customErrorDef) Name() string {
	return e.name
}

func (e *customErrorDef) Error() string {
	return fmt.Sprintf("%s(%d): %s", e.name, e.code, e.msg)
}

func DecodeCustomError(rpcErr error) (err error, ok bool) {
	if errCode, o := decodeErrorCode(rpcErr); o {
		if customErr, o := Errors[errCode]; o {
			err = customErr
			ok = true
			return
		}
	}
	return
}

func decodeErrorCode(rpcErr error) (errorCode int, ok bool) {
	var jErr *ag_jsonrpc.RPCError
	if errors.As(rpcErr, &jErr) && jErr.Data != nil {
		if root, o := jErr.Data.(map[string]interface{}); o {
			if rootErr, o := root["err"].(map[string]interface{}); o {
				if rootErrInstructionError, o := rootErr["InstructionError"]; o {
					if rootErrInstructionErrorItems, o := rootErrInstructionError.([]interface{}); o {
						if len(rootErrInstructionErrorItems) == 2 {
							if v, o := rootErrInstructionErrorItems[1].(map[string]interface{}); o {
								if v2, o := v["Custom"].(json.Number); o {
									if code, err := v2.Int64(); err == nil {
										ok = true
										errorCode = int(code)
									}
								} else if v2, o := v["Custom"].(float64); o {
									ok = true
									errorCode = int(v2)
								}
							}
						}
					}
				}
			}
		}
	}
	return
}
`))

		files = append(files, &FileWrapper{
			Name: "errors",
			File: file,
		})
	}

	// Instructions:
	for _, instruction := range idl.Instructions {
		file := NewGoFile(idl.Metadata.Name, true)
		insExportedName := ToCamel(instruction.Name)
		var args []IdlField
		for _, arg := range instruction.Args {
			idlFieldArg := IdlField{
				Name: arg.Name,
				Docs: arg.Docs,
				Type: IdlType{
					asString:         arg.Type.asString,
					asIdlTypeVec:     arg.Type.asIdlTypeVec,
					asIdlTypeOption:  arg.Type.asIdlTypeOption,
					asIdlTypeArray:   arg.Type.asIdlTypeArray,
					asIdlTypeDefined: nil,
				},
			}
			if arg.Type.asIdlTypeDefined != nil {
				idlFieldArg.Type.asIdlTypeDefined = &IdlTypeDefined{
					Defined: IdLTypeDefinedName{
						Name: arg.Type.asIdlTypeDefined.Defined.Name,
					},
				}
			}
			args = append(args, idlFieldArg)
		}

		// fmt.Println(RedBG(instruction.Name))

		{
			code := Empty().Line().Line()

			for _, doc := range instruction.Docs {
				code.Comment(doc).Line()
			}

			if len(instruction.Docs) == 0 {
				code.Commentf(
					"%s is the `%s` instruction.",
					insExportedName,
					instruction.Name,
				).Line()
			}

			code.Type().Id(insExportedName).StructFunc(func(fieldsGroup *Group) {
				for argIndex, arg := range args {
					if len(arg.Docs) > 0 {
						if argIndex > 0 {
							fieldsGroup.Line()
						}
						for _, doc := range arg.Docs {
							fieldsGroup.Comment(doc)
						}
					}
					fieldsGroup.Add(genField(arg, true)).
						Add(func() Code {
							if arg.Type.IsIdlTypeOption() {
								return Tag(map[string]string{
									"bin": "optional",
								})
							}
							return nil
						}())
				}

				fieldsGroup.Line()

				{
					lastGroupName := ""
					// Add comments of the accounts from rust docs.
					instruction.Accounts.Walk("", nil, nil, func(groupPath string, accountIndex int, parentGroup *IdlAccounts, ia *IdlAccount) bool {
						comment := &strings.Builder{}
						indent := 6
						var prepend int

						if groupPath != "" {
							thisGroupName := filepath.Base(groupPath)
							indent = len(thisGroupName) + 2
							if strings.Count(groupPath, "/") == 0 {
								prepend = 6
							} else {
								prepend = 6 + (strings.Count(groupPath, "/") * 2) + len(strings.TrimSuffix(groupPath, thisGroupName)) - 1
							}
							if lastGroupName != groupPath {
								comment.WriteString(strings.Repeat("·", prepend-1) + Sf(" %s: ", thisGroupName))
							} else {
								comment.WriteString(strings.Repeat("·", prepend+indent-1) + " ")
							}
							lastGroupName = groupPath
						}

						comment.WriteString(Sf("[%v] = ", accountIndex))
						comment.WriteString("[")
						if ia.Writable {
							comment.WriteString("WRITE")
						}
						if ia.Signer {
							if ia.Writable {
								comment.WriteString(", ")
							}
							comment.WriteString("SIGNER")
						}
						comment.WriteString("] ")
						comment.WriteString(ia.Name)

						fieldsGroup.Comment(comment.String())
						for _, doc := range ia.Docs {
							fieldsGroup.Comment(strings.Repeat("·", prepend+indent-1+6) + " " + doc)
						}
						if accountIndex < instruction.Accounts.NumAccounts()-1 {
							fieldsGroup.Comment("")
						}

						accountIndex++
						return true
					})
				}
				fieldsGroup.Qual(PkgSolanaGo, "AccountMetaSlice").Tag(map[string]string{
					"bin": "-",
				})
			})

			file.Add(code.Line())
		}

		{
			{
				code := Empty()
				code.Comment("isEventData is a marker function to indicate that this struct is an event data struct.").Line()
				code.Func().Params(Id("u").Op("*").Id(insExportedName)).Id("isEventData").Params().Block()
				file.Add(code.Line())
			}
		}

		{
			builderFuncName := formatBuilderFuncName(insExportedName)
			code := Empty()
			code.Commentf(
				"%s creates a new `%s` instruction builder.",
				builderFuncName,
				insExportedName,
			).Line()
			//
			code.Func().Id(builderFuncName).Params().Op("*").Id(insExportedName).
				BlockFunc(func(body *Group) {
					body.Id("nd").Op(":=").Op("&").Id(insExportedName).Block(
						Id("AccountMetaSlice").Op(":").Make(Qual(PkgSolanaGo, "AccountMetaSlice"), Lit(instruction.Accounts.NumAccounts())).Op(","),
					)

					// Set sysvar accounts and constant accounts:
					instruction.Accounts.Walk("", nil, nil, func(parentGroupPath string, index int, parentGroup *IdlAccounts, account *IdlAccount) bool {
						if isVar(account.Name) {
							pureVarName := getSysVarName(account.Name)
							is := isSysVar(pureVarName)
							if is {
								_, ok := sysVars[pureVarName]
								if !ok {
									panic(account)
								}
								def := Qual(PkgSolanaGo, "Meta").Call(Qual(PkgSolanaGo, pureVarName))
								if account.Writable {
									def.Dot("WRITE").Call()
								}
								if account.Signer {
									def.Dot("SIGNER").Call()
								}
								body.Id("nd").Dot("AccountMetaSlice").Index(Lit(index)).Op("=").Add(def)
							} else {
								panic(account)
							}
						} else if account.Address != "" {
							//def := Qual(PkgSolanaGo, "Meta").Call(Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(account.Address)))
							def := Qual(PkgSolanaGo, "Meta").Call(Id("Addresses").Index(Lit(account.Address)))
							addresses[account.Address] = account.Address
							accountAddresses[account.Name] = account.Address
							if account.Writable {
								def.Dot("WRITE").Call()
							}
							if account.Signer {
								def.Dot("SIGNER").Call()
							}
							body.Id("nd").Dot("AccountMetaSlice").Index(Lit(index)).Op("=").Add(def)
						}
						return true
					})

					body.Return(Id("nd"))
				})
			file.Add(code.Line())
		}
		{
			builderFuncName := formatBuilderFuncName(insExportedName) + "Ext"
			code := Empty()
			code.Commentf(
				"%s creates a new `%s` instruction builder.",
				builderFuncName,
				insExportedName,
			).Line()

			code.Func().Id(builderFuncName).Params(Id("remainingAccounts").Int()).Op("*").Id(insExportedName).
				BlockFunc(func(body *Group) {
					body.Id("nd").Op(":=").Op("&").Id(insExportedName).Block(
						Id("AccountMetaSlice").Op(":").Make(Qual(PkgSolanaGo, "AccountMetaSlice"), Lit(instruction.Accounts.NumAccounts()).Op("+").Id("remainingAccounts")).Op(","),
					)

					// Set sysvar accounts and constant accounts:
					instruction.Accounts.Walk("", nil, nil, func(parentGroupPath string, index int, parentGroup *IdlAccounts, account *IdlAccount) bool {
						if isVar(account.Name) {
							pureVarName := getSysVarName(account.Name)
							is := isSysVar(pureVarName)
							if is {
								_, ok := sysVars[pureVarName]
								if !ok {
									panic(account)
								}
								def := Qual(PkgSolanaGo, "Meta").Call(Qual(PkgSolanaGo, pureVarName))
								if account.Writable {
									def.Dot("WRITE").Call()
								}
								if account.Signer {
									def.Dot("SIGNER").Call()
								}
								body.Id("nd").Dot("AccountMetaSlice").Index(Lit(index)).Op("=").Add(def)
							} else {
								panic(account)
							}
						} else if account.Address != "" {
							def := Qual(PkgSolanaGo, "Meta").Call(Id("Addresses").Index(Lit(account.Address)))
							addresses[account.Address] = account.Address
							accountAddresses[account.Name] = account.Address
							if account.Writable {
								def.Dot("WRITE").Call()
							}
							if account.Signer {
								def.Dot("SIGNER").Call()
							}
							body.Id("nd").Dot("AccountMetaSlice").Index(Lit(index)).Op("=").Add(def)
						} else if account.PDA != nil {
							// Handle PDA accounts
							seeds := make([]Code, 0)
							for _, seed := range account.PDA.Seeds {
								if seed.Kind == "const" {
									seeds = append(seeds, Index().Byte().ValuesFunc(func(group *Group) {
										for _, v := range seed.Value {
											group.LitByte(v)
										}
									}))
								} else if seed.Kind == "account" {
									address, ok := accountAddresses[seed.Path]
									if !ok {
										seeds = append(seeds, Qual(PkgSolanaGo, "Meta").Call(Id("Addresses").Index(Lit(seed.Path))).Dot("PublicKey").Dot("Bytes").Call())
										continue
									}
									seeds = append(seeds, Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(address)).Dot("Bytes").Call())
								}
							}
							var program Code
							if account.PDA.Program != nil {
								switch account.PDA.Program.Kind {
								case "const":
									programID := solana.PublicKeyFromBytes(account.PDA.Program.Value)
									program = Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(programID.String())).Dot("String").Call()
								case "account":
									address, ok := accountAddresses[account.PDA.Program.Path]
									if ok {
										seeds = append(seeds, Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(address)).Dot("Bytes").Call())
										program = Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(address)).Dot("String").Call()
									} else {
										seeds = append(seeds, Values(Qual(PkgSolanaGo, "Meta").Call(Id("Addresses").Index(Lit(account.PDA.Program.Path))).Dot("PublicKey").Dot("Bytes").Call()))
									}
								default:
									panic(fmt.Sprintf("unsupported program kind: %s", account.PDA.Program.Kind))
								}
							}

							if program != nil {
								def := Qual(PkgSolanaGo, "Meta").Call(Qual(GetConfig().Package, "CreatePDA").Call(program, List(seeds...)))
								if account.Writable {
									def.Dot("WRITE").Call()
								}
								if account.Signer {
									def.Dot("SIGNER").Call()
								}
								body.Id("nd").Dot("AccountMetaSlice").Index(Lit(index)).Op("=").Add(def)
							}
						}
						return true
					})

					body.Return(Id("nd"))
				})

			file.Add(code.Line())
		}
		{
			// Declare methods that set the parameters of the instruction:
			code := Empty()
			for _, arg := range args {
				exportedArgName := ToCamel(arg.Name)

				code.Line().Line()
				name := "Set" + exportedArgName
				code.Commentf("%s sets the %q parameter.", name, arg.Name).Line()
				for _, doc := range arg.Docs {
					code.Comment(doc).Line()
				}

				code.Func().Params(Id("inst").Op("*").Id(insExportedName)).Id(name).
					Params(
						ListFunc(func(params *Group) {
							// Parameters:
							params.Id(arg.Name).Add(genTypeName(arg.Type))
						}),
					).
					Params(
						ListFunc(func(results *Group) {
							// Results:
							results.Op("*").Id(insExportedName)
						}),
					).
					BlockFunc(func(body *Group) {
						// Body:
						body.Id("inst").Dot(exportedArgName).Op("=").
							Add(func() Code {
								if isComplexEnum(arg.Type) {
									return nil
								}
								return Op("&")
							}()).
							Id(arg.Name)

						body.Return().Id("inst")
					})
			}

			file.Add(code.Line())
		}
		{
			// Declare methods that set/get accounts for the instruction:
			code := Empty()

			declaredReceivers := []string{}
			groupMemberIndex := 0
			instruction.Accounts.Walk("", nil, nil, func(parentGroupPath string, index int, parentGroup *IdlAccounts, account *IdlAccount) bool {
				builderStructName := insExportedName + ToCamel(parentGroupPath) + "AccountsBuilder"
				hasNestedParent := parentGroupPath != ""
				isDeclaredReceiver := SliceContains(declaredReceivers, parentGroupPath)

				if !hasNestedParent {
					groupMemberIndex = index
				}
				if hasNestedParent && !isDeclaredReceiver {
					groupMemberIndex = 0
					declaredReceivers = append(declaredReceivers, parentGroupPath)
					// many accounts (???)
					// builder struct for this accounts group:

					code.Line().Line()
					for _, doc := range parentGroup.Docs {
						code.Comment(doc).Line()
					}
					code.Type().Id(builderStructName).Struct(
						Qual(PkgSolanaGo, "AccountMetaSlice").Tag(map[string]string{
							"bin": "-",
						}),
					)

					// func that returns a new builder for this account group:
					code.Line().Line().Func().Id("New" + builderStructName).Params().Op("*").Id(builderStructName).
						BlockFunc(func(gr *Group) {
							gr.Return().Op("&").Id(builderStructName).Block(
								Id("AccountMetaSlice").Op(":").Make(Qual(PkgSolanaGo, "AccountMetaSlice"), Lit(parentGroup.Accounts.NumAccounts())).Op(","),
							)
						}).Line().Line()

					// Method on intruction builder that accepts the accounts group builder, and copies the accounts:
					code.Line().Line().Func().Params(Id("inst").Op("*").Id(insExportedName)).Id("Set" + ToCamel(parentGroup.Name) + "AccountsFromBuilder").
						Params(
							ListFunc(func(st *Group) {
								// Parameters:
								st.Id(ToLowerCamel(builderStructName)).Op("*").Id(builderStructName)
							}),
						).
						Params(
							ListFunc(func(st *Group) {
								// Results:
								st.Op("*").Id(insExportedName)
							}),
						).
						BlockFunc(func(gr *Group) {
							// Body:

							tpIndex := index
							// spew.Dump(parentGroup)
							for _, subAccount := range parentGroup.Accounts {
								if subAccount.IdlAccount != nil {
									exportedAccountName := ToCamel(subAccount.IdlAccount.Name)

									def := Id("inst").Dot("AccountMetaSlice").Index(Lit(tpIndex)).
										Op("=").Id(ToLowerCamel(builderStructName)).Dot(formatAccountAccessorName("Get", exportedAccountName)).Call()

									gr.Add(def)
								}
								tpIndex++
							}

							gr.Return().Id("inst")
						})
				}

				{
					exportedAccountName := ToCamel(account.Name)
					lowerAccountName := ToLowerCamel(account.Name)

					var receiverTypeName string
					if parentGroupPath == "" {
						receiverTypeName = insExportedName
					} else {
						receiverTypeName = builderStructName
					}

					code.Add(genAccountGettersSetters(
						receiverTypeName,
						account,
						groupMemberIndex,
						exportedAccountName,
						lowerAccountName,
						instruction.Accounts,
						addresses,
						accountAddresses,
						instruction.Args,
						&idl,
					))
					groupMemberIndex++
				}
				return true
			})

			file.Add(code.Line())
		}
		{
			// Declare `AddRemainingAccounts` method on instruction:
			code := Empty()

			code.Line().Line().Func().Params(Id("inst").Op("*").Id(insExportedName)).Id("AddRemainingAccounts").Params(
				Id("remainingAccounts").Index().Qual(PkgSolanaGo, "PublicKey"),
			).Params(Op("*").Id(insExportedName)).
				Block(
					jen.Id("accounts").Op(":=").Lit(instruction.Accounts.NumAccounts()),
					jen.For(
						jen.Id("i").Op(",").Id("_").Op(":=").Range().Id("remainingAccounts"),
					).Block(
						jen.Id("index").Op(":=").Id("accounts").Op("+").Id("i"),
						jen.Id("inst").Dot("AccountMetaSlice").Index(jen.Id("index")).Op("=").Qual(PkgSolanaGo, "NewAccountMeta").Call(jen.Id("remainingAccounts").Index(jen.Id("i")), jen.True(), jen.False())),
					Return(Id("inst")),
				)
			file.Add(code.Line())
		}
		{
			// Declare `Build` method on instruction:
			code := Empty()

			code.Line().Line().Func().Params(Id("inst").Id(insExportedName)).Id("Build").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Op("*").Id("Instruction")
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:

					var typeIDCode Code

					GetConfig().TypeID.
						On(
							TypeIDNameSlice{
								TypeIDUvarint32,
							},
							func() {
								typeIDCode = Qual(PkgBinary, "TypeIDFromUvarint32").Call(Id("Instruction_" + insExportedName))
							},
						).
						On(
							TypeIDNameSlice{
								TypeIDUint32,
							},
							func() {
								typeIDCode = Qual(PkgBinary, "TypeIDFromUint32").Call(Id("Instruction_"+insExportedName), Qual("encoding/binary", "LittleEndian"))
							},
						).
						On(
							TypeIDNameSlice{
								TypeIDUint8,
							},
							func() {
								typeIDCode = Qual(PkgBinary, "TypeIDFromUint8").Call(Id("Instruction_" + insExportedName))
							},
						).
						On(
							TypeIDNameSlice{
								TypeIDAnchor,
							},
							func() {
								typeIDCode = Id("Instruction_" + insExportedName)
							},
						).
						On(
							TypeIDNameSlice{
								TypeIDNoType,
							},
							func() {
								// TODO
							},
						)

					body.Return().Op("&").Id("Instruction").Values(
						Dict{
							Id("BaseVariant"): Qual(PkgBinary, "BaseVariant").Values(
								Dict{
									Id("TypeID"): typeIDCode,
									Id("Impl"):   Id("inst"),
								},
							),
						},
					)
				})
			file.Add(code.Line())
		}
		{
			// Declare `ValidateAndBuild` method on instruction:
			code := Empty()

			code.Line().Line().
				Comment("ValidateAndBuild validates the instruction parameters and accounts;").
				Line().
				Comment("if there is a validation error, it returns the error.").
				Line().
				Comment("Otherwise, it builds and returns the instruction.").
				Line().
				Func().Params(Id("inst").Id(insExportedName)).Id("ValidateAndBuild").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Op("*").Id("Instruction")
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.If(
						Err().Op(":=").Id("inst").Dot("Validate").Call(),
						Err().Op("!=").Nil(),
					).Block(
						Return(Nil(), Err()),
					)

					body.Return(Id("inst").Dot("Build").Call(), Nil())
				})
			file.Add(code.Line())
		}
		{
			// Declare `Validate` method on instruction:
			code := Empty()

			code.Line().Line().Func().Params(Id("inst").Op("*").Id(insExportedName)).Id("Validate").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					if len(args) > 0 {
						body.Comment("Check whether all (required) parameters are set:")

						body.BlockFunc(func(paramVerifyBody *Group) {
							for _, arg := range args {
								exportedArgName := ToCamel(arg.Name)

								// Optional params can be empty.
								if arg.Type.IsIdlTypeOption() {
									continue
								}

								paramVerifyBody.If(Id("inst").Dot(exportedArgName).Op("==").Nil()).Block(
									Return(
										Qual("errors", "New").Call(Lit(Sf("%s parameter is not set", exportedArgName))),
									),
								)
							}
						})
						body.Line()
					}

					body.Comment("Check whether all (required) accounts are set:")
					body.BlockFunc(func(accountValidationBlock *Group) {
						instruction.Accounts.Walk("", nil, nil, func(groupPath string, accountIndex int, parentGroup *IdlAccounts, ia *IdlAccount) bool {
							exportedAccountName := ToCamel(filepath.Join(groupPath, ia.Name))

							if ia.Optional {
								accountValidationBlock.Line().Commentf(
									"[%v] = %s is optional",
									accountIndex,
									exportedAccountName,
								).Line()
							} else {
								accountValidationBlock.If(Id("inst").Dot("AccountMetaSlice").Index(Lit(accountIndex)).Op("==").Nil()).Block(
									Return(Qual("errors", "New").Call(Lit(Sf("accounts.%s is not set", exportedAccountName)))),
								)
							}

							return true
						})
					})

					body.Return(Nil())
				})
			file.Add(code.Line())
		}
		{
			// Declare `EncodeToTree(parent treeout.Branches)` method in instruction:
			code := Empty()

			code.Line().Line().Func().Params(Id("inst").Op("*").Id(insExportedName)).Id("EncodeToTree").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("parent").Qual(PkgTreeout, "Branches")
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:

					body.Id("parent").Dot("Child").Call(Qual(PkgFormat, "Program").Call(Id("ProgramName"), Id("ProgramID"))).Op(".").
						Line().Comment("").Line().
						Id("ParentFunc").Parens(Func().Parens(Id("programBranch").Qual(PkgTreeout, "Branches")).BlockFunc(
						func(programBranchGroup *Group) {
							programBranchGroup.Id("programBranch").Dot("Child").Call(Qual(PkgFormat, "Instruction").Call(Lit(insExportedName))).Op(".").
								Line().Comment("").Line().
								Id("ParentFunc").Parens(Func().Parens(Id("instructionBranch").Qual(PkgTreeout, "Branches")).BlockFunc(
								func(instructionBranchGroup *Group) {

									instructionBranchGroup.Line().Comment("Parameters of the instruction:")

									instructionBranchGroup.Id("instructionBranch").Dot("Child").Call(Lit(Sf("Params[len=%v]", len(args)))).Dot("ParentFunc").Parens(Func().Parens(Id("paramsBranch").Qual(PkgTreeout, "Branches")).BlockFunc(func(paramsBranchGroup *Group) {
										longest := treeFindLongestNameFromFields(args)
										for _, arg := range args {
											exportedArgName := ToCamel(arg.Name)
											paramsBranchGroup.Id("paramsBranch").Dot("Child").
												Call(
													Qual(PkgFormat, "Param").Call(
														Lit(strings.Repeat(" ", longest-len(exportedArgName))+exportedArgName+StringIf(arg.Type.IsIdlTypeOption(), " (OPT)")),
														Add(CodeIf(!arg.Type.IsIdlTypeOption() && !isComplexEnum(arg.Type), Op("*"))).Id("inst").Dot(exportedArgName),
													),
												)
										}
									}))

									instructionBranchGroup.Line().Comment("Accounts of the instruction:")

									instructionBranchGroup.Id("instructionBranch").Dot("Child").Call(Lit(Sf("Accounts[len=%v]", instruction.Accounts.NumAccounts()))).Dot("ParentFunc").Parens(
										Func().Parens(Id("accountsBranch").Qual(PkgTreeout, "Branches")).BlockFunc(func(accountsBranchGroup *Group) {

											longest := treeFindLongestNameFromAccounts(instruction.Accounts)
											instruction.Accounts.Walk("", nil, nil, func(groupPath string, accountIndex int, parentGroup *IdlAccounts, ia *IdlAccount) bool {

												cleanedName := treeFormatAccountName(ia.Name)

												exportedAccountName := filepath.Join(groupPath, cleanedName)

												access := Id("accountsBranch").Dot("Child").Call(Qual(PkgFormat, "Meta").Call(Lit(strings.Repeat(" ", longest-len(exportedAccountName))+exportedAccountName), Id("inst").Dot("AccountMetaSlice").Dot("Get").Call(Lit(accountIndex))))
												accountsBranchGroup.Add(access)
												return true
											})
										}))
								}))
						}))
				})
			file.Add(code.Line())
		}

		{
			// Declare `MarshalWithEncoder(encoder *bin.Encoder) error` method on instruction:
			file.Add(
				genMarshalWithEncoder_struct(
					&idl,
					false,
					insExportedName,
					"",
					args,
					true,
				),
			)
		}

		{
			// Declare `UnmarshalWithDecoder(decoder *bin.Decoder) error` method on instruction:
			file.Add(
				genUnmarshalWithDecoder_struct(
					&idl,
					false,
					insExportedName,
					"",
					args,
					bin.TypeID{},
				))
		}

		{
			// Declare instruction initializer func:
			paramNames := []string{}
			for _, arg := range args {
				paramNames = append(paramNames, arg.Name)
			}
			code := Empty()
			name := "New" + insExportedName + "Instruction"
			code.Commentf("%s declares a new %s instruction with the provided parameters and accounts.", name, insExportedName)
			code.Line()
			code.Func().Id(name).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						{
							for argIndex, arg := range args {
								paramNames = append(paramNames, arg.Name)
								params.Add(func() Code {
									if argIndex == 0 {
										return Line().Comment("Parameters:")
									}
									return Empty()
								}()).Line().Id(arg.Name).Add(genTypeName(arg.Type))
							}
						}
						{
							instruction.Accounts.Walk("", nil, nil, func(parentGroupPath string, index int, parentGroup *IdlAccounts, account *IdlAccount) bool {
								// skip sysvars:
								if isSysVar(account.Name) {
									return true
								}
								var accountName string
								if parentGroupPath == "" {
									accountName = ToLowerCamel(account.Name)
								} else {
									accountName = ToLowerCamel(parentGroupPath + "/" + ToLowerCamel(account.Name))
								}

								if SliceContains(paramNames, accountName) {
									accountName = accountName + "Account"
								}

								params.Add(func() Code {
									if index == 0 {
										return Line().Comment("Accounts:").Line()
									}
									return Line()
								}()).Id(accountName).Qual(PkgSolanaGo, "PublicKey")
								return true
							})
						}
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Op("*").Id(insExportedName)
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					builder := body.Return().Id(formatBuilderFuncName(insExportedName)).Call()
					{
						for _, arg := range args {
							exportedArgName := ToCamel(arg.Name)
							builder.Op(".").Line().Id("Set" + exportedArgName).Call(Id(arg.Name))
						}
					}

					{
						declaredReceivers := []string{}
						instruction.Accounts.Walk("", nil, nil, func(parentGroupPath string, index int, parentGroup *IdlAccounts, account *IdlAccount) bool {
							// skip sysvars:
							if isSysVar(account.Name) {
								return true
							}
							var accountName string
							if parentGroupPath == "" {
								accountName = ToLowerCamel(account.Name)
							} else {
								// TODO
							}

							if SliceContains(paramNames, accountName) {
								accountName = accountName + "Account"
							}

							builderStructName := insExportedName + ToCamel(parentGroupPath) + "AccountsBuilder"
							hasNestedParent := parentGroupPath != ""
							isDeclaredReceiver := SliceContains(declaredReceivers, parentGroupPath)

							if hasNestedParent && !isDeclaredReceiver {
								declaredReceivers = append(declaredReceivers, parentGroupPath)
								builder.Op(".").Line().Id("Set" + ToCamel(parentGroup.Name) + "AccountsFromBuilder").Call(
									Line().Id("New" + builderStructName).Call().
										Add(
											DoGroup(func(gr *Group) {
												// Body:
												for subIndex, subAccount := range parentGroup.Accounts {
													if subAccount.IdlAccount != nil {
														exportedAccountName := ToCamel(subAccount.IdlAccount.Name)
														accountName = ToLowerCamel(parentGroupPath + "/" + ToLowerCamel(exportedAccountName))

														gr.Op(".").Add(func() Code {
															if subIndex == 0 {
																return Line().Line()
															}
															return Line()
														}()).Id(formatAccountAccessorName("Set", exportedAccountName)).Call(Id(accountName))

														if subIndex == len(parentGroup.Accounts)-1 {
															gr.Op(",").Line()
														}
													}
												}
											}),
										),
								)
							}

							if !hasNestedParent {
								builder.Op(".").Line().Id(formatAccountAccessorName("Set", ToCamel(account.Name))).Call(Id(accountName))
							}

							return true
						})
					}

					// builder.Op(".").Line().Id("Build").Call()
				})

			file.Add(code.Line())
		}
		////
		files = append(files, &FileWrapper{
			Name: strings.ToLower(insExportedName),
			File: file,
		})
	}

	// add configurable address map file
	{
		file := NewGoFile(idl.Metadata.Name, false)
		code := Empty().Var().Id("Addresses").Op("=").Map(String()).Qual(PkgSolanaGo, "PublicKey").Values(DictFunc(func(dict Dict) {
			for address := range addresses {
				dict[Lit(address)] = Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(address))
			}
		}))
		file.Add(code)
		files = append(files, &FileWrapper{
			Name: "addresses",
			File: file,
		})
	}

	// add constants file
	{
		file := NewGoFile(idl.Metadata.Name, false)
		code := Empty()
		for _, c := range idl.Constants {
			code.Line().Var().Id(fmt.Sprintf("CONST_%s", c.Name)).Op("=")
			typ := c.Type.GetString()
			switch typ {
			case "string":
				v, err := strconv.Unquote(c.Value)
				if err != nil {
					panic(fmt.Sprintf("failed to parse constant: %s", spew.Sdump(c)))
				}
				code.Lit(v)
			case "u16":
				v, err := strconv.ParseInt(c.Value, 10, 16)
				if err != nil {
					panic(fmt.Sprintf("failed to parse constant: %s", spew.Sdump(c)))
				}
				code.Lit(int(v))
			case "i64":
				v, err := strconv.ParseInt(c.Value, 10, 64)
				if err != nil {
					panic(fmt.Sprintf("failed to parse constant: %s", spew.Sdump(c)))
				}
				code.Lit(int(v))
			case "pubkey":
				code.Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(c.Value))
			default:
				panic(fmt.Sprintf("unsupportd constant: %s", spew.Sdump(c)))
			}

		}
		file.Add(code)
		files = append(files, &FileWrapper{
			Name: "constants",
			File: file,
		})
	}

	// add pdas file and CreatePDA method
	{
		file := NewGoFile(idl.Metadata.Name, false)
		// to generate import statements
		file.Add(Var().Defs(
			Id("_").Op("*").Qual("github.com/gagliardetto/solana-go", "PublicKey").Op("=").Nil(),
			Id("_").Op("*").Qual("fmt", "Formatter").Op("=").Nil(),
		))

		file.Add(Empty().Id(`
// CreatePDA creates a Program Derived Address (PDA) for the given seeds and program ID.
func CreatePDA(programID string, seeds ...[]byte) ag_solanago.PublicKey {
	// Convert the program ID to a PublicKey
	programPubKey, err := ag_solanago.PublicKeyFromBase58(programID)
	if err != nil {
		panic(err)
	}

	// Find the PDA
	pda, _, err := ag_solanago.FindProgramAddress(seeds, programPubKey)
	if err != nil {
		panic(err)
	}

	return pda
}
`))

		files = append(files, &FileWrapper{
			Name: "programderivedaccounts",
			File: file,
		})
	}

	{
		testFiles, err := genTestingFuncs(idl)
		if err != nil {
			return nil, err
		}
		files = append(files, testFiles...)
	}

	{
		file := NewGoFile(idl.Metadata.Name, false)
		// to generate import statements
		file.Add(Var().Defs(
			Id("_").Op("*").Qual("github.com/gagliardetto/solana-go", "PublicKey").Op("=").Nil(),
			Id("_").Op("*").Qual("fmt", "Formatter").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgBinary, "Decoder").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgSolanaGoRpc, "Client").Op("=").Nil(),
			Id("_").Op("*").Qual(PkgBase58, "Alphabet").Op("=").Nil(),
			Id("_").Op("*").Qual("reflect", "Type").Op("=").Nil(),
		))

		file.Add().Empty().Var().Id("innerInstructionTypes").Op("=").Map(Index(Lit(8)).Byte()).Qual("reflect", "Type").Values(DictFunc(func(d Dict) {
			for _, ins := range idl.Instructions {
				insExportedName := ToCamel(ins.Name)
				d[Id("Instruction_"+insExportedName)] = Id("reflect.TypeOf(" + insExportedName + "{})")
			}
		}))

		file.Add(Empty().Var().Id("innerInstructionToNames").Op("=").Map(Index(Lit(8)).Byte()).String().Values(DictFunc(func(d Dict) {
			for _, ins := range idl.Instructions {
				insExportedName := ToCamel(ins.Name)
				d[Id("Instruction_"+insExportedName)] = Lit(ins.Name)
			}
		})))

		file.Add(Empty().Var().Id("innerInstructionToEventName").Op("=").Map(Index(Lit(8)).Byte()).String().Values(DictFunc(func(d Dict) {
			for _, ins := range idl.Instructions {
				insExportedName := ToCamel(ins.Name)
				d[Id("Instruction_"+insExportedName)] = Lit(ToCamel(ins.Name))
			}
		})))

		file.Add().Empty().Id(
			`

type InnerInstructionEvent struct {
	Name     string
	Data     EventData
}

func DecodeInnerInstructions(txData *ag_rpc.GetTransactionResult, targetProgramId ag_solanago.PublicKey) (events []*InnerInstructionEvent, err error) {
	var innerInstructions []*InnerInstructionEvent

	var tx *ag_solanago.Transaction
	if tx, err = txData.Transaction.GetTransaction(); err != nil {
		return nil, err
	}

	for _, innerInstruction := range txData.Meta.InnerInstructions {
		for _, instruction := range innerInstruction.Instructions {
			if tx.Message.AccountKeys[instruction.ProgramIDIndex] != targetProgramId {
				continue
			}

			rawData, err := ag_base58.Decode(instruction.Data.String())
			if err != nil {
				return nil, fmt.Errorf("error decoding instruction data from Base58: %w", err)
			}


			discriminator := ag_binary.TypeID(rawData[:8])

			if eventType, ok := innerInstructionTypes[discriminator]; ok {
				eventData := reflect.New(eventType).Interface().(EventData)
				decoder := ag_binary.NewBorshDecoder(rawData[8:])
				if err := decoder.Decode(eventData); err != nil {
					return nil, fmt.Errorf("error decoding instruction: %w", err)
				}
				event := &InnerInstructionEvent{
					Name:     innerInstructionToEventName[discriminator],
					Data:     eventData,
				}

				accounts:= make(ag_solanago.AccountMetaSlice, len(instruction.Accounts))
				for i, accIndex := range instruction.Accounts {
					accounts[i] = &ag_solanago.AccountMeta{PublicKey: tx.Message.AccountKeys[accIndex]}
				}

				// add accounts to event
				if v, ok:= event.Data.(ag_solanago.AccountsSettable); ok {
					err := v.SetAccounts(accounts)
					if err != nil {
						return nil, fmt.Errorf("error setting accounts for instruction: %w", err)
					}
				} 
				
				innerInstructions = append(innerInstructions, event)
			}
		}
	}

	return innerInstructions, nil
}

`)

		files = append(files, &FileWrapper{
			Name: "innerinstructions",
			File: file,
		})
	}

	return files, nil
}

//
//func findAddressForAccountPath(idl IDL, p string) string {
//
//}

func genAccountGettersSetters(
	receiverTypeName string,
	account *IdlAccount,
	index int,
	exportedAccountName string,
	lowerAccountName string,
	accounts []IdlAccountItem,
	addresses map[string]string,
	accountAddresses map[string]string,
	args []IdlField,
	idl *IDL,
) Code {
	code := Empty()

	{
		code.Line().Line()
		name := formatAccountAccessorName("Set", exportedAccountName)
		code.Commentf("%s sets the %q account.", name, account.Name).Line()
		for _, doc := range account.Docs {
			code.Comment(doc).Line()
		}

		// Create account setters:
		code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id(name).
			Params(
				ListFunc(func(params *Group) {
					// Parameters:
					params.Id(lowerAccountName).Qual(PkgSolanaGo, "PublicKey")
				}),
			).
			Params(
				ListFunc(func(results *Group) {
					// Results:
					results.Op("*").Id(receiverTypeName)
				}),
			).
			BlockFunc(func(body *Group) {
				// Body:
				def := Id("inst").Dot("AccountMetaSlice").Index(Lit(index)).
					Op("=").Qual(PkgSolanaGo, "Meta").Call(Id(lowerAccountName))
				if account.Writable {
					def.Dot("WRITE").Call()
				}
				if account.Signer {
					def.Dot("SIGNER").Call()
				}
				body.Add(def)

				body.Return().Id("inst")
			})
	}

	{
		if account.PDA != nil {
			code.Line().Line()
			accessorName := strings.TrimSuffix(formatAccountAccessorName("Find", exportedAccountName), "Account") + "Address"

			// find seeds
			seedValues := make([][]byte, len(account.PDA.Seeds))
			seedRefs := make([]string, len(account.PDA.Seeds))
			seedTypes := make([]IdlType, len(account.PDA.Seeds))

			var seedProgramValue []byte
			if account.PDA.Program != nil {
				switch account.PDA.Program.Kind {
				case "const":
					if account.PDA.Program.Value == nil {
						panic("cannot handle non-const type program value in PDA seeds" + account.Address)
					}
					seedProgramValue = account.PDA.Program.Value
				case "account":
					address, ok := accountAddresses[account.PDA.Program.Path]
					if !ok {
						panic("cannot find related account for PDA program " + account.PDA.Program.Path)
					}
					seedProgramValue = solana.MustPublicKeyFromBase58(address).Bytes()
				default:
					panic("unsupported PDA program kind: " + account.PDA.Program.Kind)
				}
			}

		OUTER:
			for i, seedDef := range account.PDA.Seeds {
				if seedDef.Value != nil { // type: const
					seedValues[i] = seedDef.Value
				} else {
					// First check if it's an account reference
					for _, acc := range accounts {
						if acc.IdlAccount.Name == seedDef.Path {
							seedRefs[i] = ToLowerCamel(acc.IdlAccount.Name)
							continue OUTER
						}
					}

					for _, argv := range args {
						argvName := strings.TrimPrefix(argv.Name, "_")
						if argvName == seedDef.Path {
							seedRefs[i] = ToLowerCamel(argv.Name)
							seedTypes[i] = argv.Type
							continue OUTER
						}
					}

					//// Handle non-const program account
					//if account.PDA.Program != nil && account.PDA.Program.Kind == "account" {
					//	found := false
					//	for _, acc := range accounts {
					//		if acc.IdlAccount.Name == account.PDA.Program.Path {
					//			seedProgramValue = solana.MustPublicKeyFromBase58(acc.IdlAccount.Address).Bytes()
					//			found = true
					//			break
					//		}
					//	}
					//	if !found {
					//		panic(fmt.Sprintf("cannot find related account for PDA program %s", account.PDA.Program.Path))
					//	}
					//}

					// Then check if it's an argument field reference
					parts := strings.Split(seedDef.Path, ".")
					if len(parts) == 2 {
						// Find the argument type
						var argType IdlType
						for _, arg := range args {
							if arg.Name == parts[0] {
								// Found the argument, now need to find the field type
								if arg.Type.IsIdlTypeDefined() {
									// Look up the defined type
									definedType := idl.Types.GetByName(arg.Type.GetIdlTypeDefined().Defined.Name)
									if definedType != nil && definedType.Type.Fields != nil {
										// Find the field
										for _, field := range *definedType.Type.Fields {
											if field.Name == parts[1] {
												argType = field.Type
												break
											}
										}
									}
								}
								break
							}
						}
						for _, typ := range idl.Types {
							if typ.Name == seedDef.Account {
								for _, field := range *typ.Type.Fields {
									if field.Name == parts[1] {
										argType = field.Type
										break
									}
								}
							}
						}

						paramName := ToLowerCamel(parts[0] + "_" + parts[1])

						seedTypes[i] = argType

						// Update the function signature to use the correct type
						seedRefs[i] = paramName
						continue OUTER
					}

					panic(fmt.Sprintf("cannot find related account or argument path %q", seedDef.Path))
				}
			}

			internalAccessorName := "find" + accessorName
			code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id(internalAccessorName).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						for i, seedRef := range seedRefs {
							if seedRef != "" {
								if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
									params.Id(seedRef).Index(Lit(32)).Byte()
								} else if seedTypes[i].asString == "i64" {
									params.Id(seedRef).Index(Lit(8)).Byte()
								} else {
									params.Id(seedRef).Qual(PkgSolanaGo, "PublicKey")
								}
							}
						}
						params.Id("knownBumpSeed").Uint8()
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Id("pda").Qual(PkgSolanaGo, "PublicKey")
						results.Id("bumpSeed").Uint8()
						results.Id("err").Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.Add(Var().Id("seeds").Index().Index().Byte())

					for i, seedValue := range seedValues {
						if seedValue != nil {
							if utf8.Valid(seedValue) {
								if bytes.Equal(seedValue, make([]byte, len(seedValue))) {
									body.Comment("const: Pubkey.Default{}")
								} else {
									body.Commentf("const: %s", string(seedValue))
								}
								body.Add(Id("seeds").Op("=").Append(Id("seeds"), Index().Byte().ValuesFunc(func(group *Group) {
									for _, b := range seedValue {
										group.LitByte(b)
									}
								})))
							} else {
								body.Commentf("const (raw): %+v", seedValue)
								body.Add(Id("seeds").Op("=").Append(Id("seeds"), Index().Byte().ValuesFunc(func(group *Group) {
									for _, v := range seedValue {
										group.LitByte(v)
									}
								})))
							}
						} else {
							seedRef := seedRefs[i]
							body.Commentf("path: %s", seedRef)
							if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
								body.Add(Id("seeds").Op("=").Append(Id("seeds"), Id(seedRef).Index())) // Just pass the byte array directly
							} else {
								body.Add(Id("seeds").Op("=").Append(Id("seeds"), Id(seedRef).Dot("Bytes").Call()))
							}
						}
					}

					body.Line()

					seedProgramRef := Id("ProgramID")
					if seedProgramValue != nil {
						seedProgramRef = Id("programID")
						address := solana.PublicKeyFromBytes(seedProgramValue).String()
						body.Add(Id("programID").Op(":=").Id("Addresses").Index(Lit(address)))
						addresses[address] = address
					}

					body.Line()

					body.Add(
						If(Id("knownBumpSeed").Op("!=").Lit(0)).BlockFunc(func(group *Group) {
							group.Add(Id("seeds").Op("=").Append(Id("seeds"), Index().Byte().Values(Byte().Call(Id("bumpSeed")))))
							group.Add(List(Id("pda"), Id("err")).Op("=").Add(Qual(PkgSolanaGo, "CreateProgramAddress").Call(Id("seeds"), seedProgramRef)))
						}).
							Else().BlockFunc(func(group *Group) {
							group.Add(List(Id("pda"), Id("bumpSeed"), Id("err")).Op("=").Add(Qual(PkgSolanaGo, "FindProgramAddress").Call(Id("seeds"), seedProgramRef)))
						}),
					)

					body.Return()
				})

			code.Line().Line()
			accessorName2 := accessorName + "WithBumpSeed"
			code.Commentf("%s calculates %s account address with given seeds and a known bump seed.", accessorName2, exportedAccountName).Line()
			code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id(accessorName2).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						for i, seedRef := range seedRefs {
							if seedRef != "" {
								if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
									params.Id(seedRef).Index(Lit(32)).Byte()
								} else if seedTypes[i].asString == "i64" {
									params.Id(seedRef).Index(Lit(8)).Byte()
								} else {
									params.Id(seedRef).Qual(PkgSolanaGo, "PublicKey")
								}
							}
						}
						params.Id("bumpSeed").Uint8()
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Id("pda").Qual(PkgSolanaGo, "PublicKey")
						results.Id("err").Error()
					}),
				).
				BlockFunc(func(body *Group) {
					body.Add(List(Id("pda"), Id("_"), Id("err")).Op("=").Id("inst").Dot(internalAccessorName).CallFunc(func(group *Group) {
						for _, seedRef := range seedRefs {
							if seedRef != "" {
								group.Add(Id(seedRef))
							}
						}
						group.Add(Id("bumpSeed"))
						return
					}))

					body.Return()
				})

			code.Line().Line()
			code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id("Must" + accessorName2).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						for i, seedRef := range seedRefs {
							if seedRef != "" {
								if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
									params.Id(seedRef).Index(Lit(32)).Byte()
								} else if seedTypes[i].asString == "i64" {
									params.Id(seedRef).Index(Lit(8)).Byte()
								} else {
									params.Id(seedRef).Qual(PkgSolanaGo, "PublicKey")
								}
							}
						}
						params.Id("bumpSeed").Uint8()
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Id("pda").Qual(PkgSolanaGo, "PublicKey")
					}),
				).
				BlockFunc(func(body *Group) {
					body.Add(List(Id("pda"), Id("_"), Id("err")).Op(":=").Id("inst").Dot(internalAccessorName).CallFunc(func(group *Group) {
						for _, seedRef := range seedRefs {
							if seedRef != "" {
								group.Add(Id(seedRef))
							}
						}
						group.Add(Id("bumpSeed"))
						return
					}))

					body.Add(If(Id("err").Op("!=").Nil()).Block(Panic(Id("err"))))

					body.Return()
				})

			code.Line().Line()
			accessorName3 := accessorName
			code.Commentf("%s finds %s account address with given seeds.", accessorName3, exportedAccountName).Line()
			code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id(accessorName3).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						for i, seedRef := range seedRefs {
							if seedRef != "" {
								if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
									params.Id(seedRef).Index(Lit(32)).Byte()
								} else if seedTypes[i].asString == "i64" {
									params.Id(seedRef).Index(Lit(8)).Byte()
								} else {
									params.Id(seedRef).Qual(PkgSolanaGo, "PublicKey")
								}
							}
						}
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Id("pda").Qual(PkgSolanaGo, "PublicKey")
						results.Id("bumpSeed").Uint8()
						results.Id("err").Error()
					}),
				).
				BlockFunc(func(body *Group) {
					body.Add(List(Id("pda"), Id("bumpSeed"), Id("err")).Op("=").Id("inst").Dot(internalAccessorName).CallFunc(func(group *Group) {
						for _, seedRef := range seedRefs {
							if seedRef != "" {
								group.Add(Id(seedRef))
							}
						}
						group.Add(Lit(0))
						return
					}))

					body.Return()
				})

			code.Line().Line()
			code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id("Must" + accessorName3).
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						for i, seedRef := range seedRefs {
							if seedRef != "" {
								if seedTypes[i].IsArray() && seedTypes[i].GetArray().Elem.GetString() == "u8" {
									params.Id(seedRef).Index(Lit(32)).Byte()
								} else if seedTypes[i].asString == "i64" {
									params.Id(seedRef).Index(Lit(8)).Byte()
								} else {
									params.Id(seedRef).Qual(PkgSolanaGo, "PublicKey")
								}
							}
						}
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Id("pda").Qual(PkgSolanaGo, "PublicKey")
					}),
				).
				BlockFunc(func(body *Group) {
					body.Add(List(Id("pda"), Id("_"), Id("err")).Op(":=").Id("inst").Dot(internalAccessorName).CallFunc(func(group *Group) {
						for _, seedRef := range seedRefs {
							if seedRef != "" {
								group.Add(Id(seedRef))
							}
						}
						group.Add(Lit(0))
						return
					}))

					body.Add(If(Id("err").Op("!=").Nil()).Block(Panic(Id("err"))))

					body.Return()
				})
		}
	}

	{ // Create account getters:
		code.Line().Line()
		name := formatAccountAccessorName("Get", exportedAccountName)
		if account.Optional {
			code.Commentf("%s gets the %q account (optional).", name, account.Name).Line()
		} else {
			code.Commentf("%s gets the %q account.", name, account.Name).Line()
		}
		for _, doc := range account.Docs {
			code.Comment(doc).Line()
		}
		code.Func().Params(Id("inst").Op("*").Id(receiverTypeName)).Id(name).
			Params(
				ListFunc(func(params *Group) {
					// Parameters:
				}),
			).
			Params(
				ListFunc(func(results *Group) {
					// Results:
					results.Op("*").Qual(PkgSolanaGo, "AccountMeta")
				}),
			).
			BlockFunc(func(body *Group) {
				// Body:
				body.Return(Id("inst").Dot("AccountMetaSlice").Dot("Get").Call(Lit(index)))
			})
	}

	return code
}

func genProgramBoilerplate(idl IDL) (*File, error) {
	file := NewGoFile(idl.Metadata.Name, true)
	for _, programDoc := range idl.Docs {
		file.HeaderComment(programDoc)
	}

	{
		// ProgramID variable:
		code := Empty()

		hasAddress := idl.Metadata != nil && idl.Metadata.Address != ""
		code.Var().Id("ProgramID").Qual(PkgSolanaGo, "PublicKey").
			Add(
				func() Code {
					if hasAddress {
						return Op("=").Qual(PkgSolanaGo, "MustPublicKeyFromBase58").Call(Lit(idl.Metadata.Address))
					}
					return nil
				}(),
			)
		file.Add(code.Line())
	}
	{
		// `SetProgramID` func:
		code := Empty()
		code.Func().Id("SetProgramID").Params(Id("PublicKey").Qual(PkgSolanaGo, "PublicKey")).Block(
			Id("ProgramID").Op("=").Id("PublicKey"),
			Qual(PkgSolanaGo, "RegisterInstructionDecoder").Call(Id("ProgramID"), Id("registryDecodeInstruction")),
		)
		file.Add(code.Line())
	}
	{
		// ProgramName variable:
		code := Empty()
		programName := ToCamel(idl.Metadata.Name)
		code.Const().Id("ProgramName").Op("=").Lit(programName)
		file.Add(code.Line())
	}
	{
		// register decoder:
		code := Empty()
		code.Func().Id("init").Call().Block(
			// TODO: check for pointer instead.
			If(
				Op("!").Id("ProgramID").Dot("IsZero").Call(),
			).Block(
				Qual(PkgSolanaGo, "RegisterInstructionDecoder").Call(Id("ProgramID"), Id("registryDecodeInstruction")),
			),
		)
		file.Add(code.Line())
	}

	{
		// Instruction ID enum:
		GetConfig().TypeID.
			On(
				TypeIDNameSlice{
					TypeIDUvarint32,
					TypeIDUint32,
					TypeIDUint8,
				},
				func() {

					code := Empty()
					code.Const().Parens(
						DoGroup(func(gr *Group) {
							for instructionIndex, instruction := range idl.Instructions {
								insExportedName := ToCamel(instruction.Name)

								ins := Empty().Line()
								for _, doc := range instruction.Docs {
									ins.Comment(doc).Line()
								}
								ins.Id("Instruction_" + insExportedName)

								if instructionIndex == 0 {
									switch GetConfig().TypeID {
									case TypeIDUvarint32, TypeIDUint32:
										ins.Uint32().Op("=").Iota().Line()
									case TypeIDUint8:
										ins.Uint8().Op("=").Iota().Line()
									}
								}
								gr.Add(ins.Line().Line())
							}
						}),
					)
					file.Add(code.Line())

				},
			).
			On(
				TypeIDNameSlice{
					TypeIDAnchor,
				},
				func() {
					code := Empty()
					code.Var().Parens(
						DoGroup(func(gr *Group) {
							for _, instruction := range idl.Instructions {
								insExportedName := ToCamel(instruction.Name)

								ins := Empty().Line()
								for _, doc := range instruction.Docs {
									ins.Comment(doc).Line()
								}
								toBeHashed := sighash.ToSnakeForSighash(instruction.Name)
								if GetConfig().Debug {
									ins.Comment(Sf(`hash("%s:%s")`, bin.SIGHASH_GLOBAL_NAMESPACE, toBeHashed)).Line()
								}
								ins.Id("Instruction_" + insExportedName)

								ins.Op("=").Qual(PkgBinary, "TypeID").Call(
									Index(Lit(8)).Byte().Op("{").ListFunc(func(byteGroup *Group) {
										sighash := bin.SighashTypeID(bin.SIGHASH_GLOBAL_NAMESPACE, toBeHashed)
										if instruction.Discriminator != nil {
											sighash = *instruction.Discriminator
										}
										for _, byteVal := range sighash[:] {
											byteGroup.Lit(int(byteVal))
										}
									}).Op("}"),
								)
								gr.Add(ins.Line().Line())
							}
						}),
					)
					file.Add(code.Line())
				},
			).
			On(
				TypeIDNameSlice{
					TypeIDNoType,
				},
				func() {
					// TODO
				},
			)
	}
	{
		// Declare `InstructionIDToName` function:
		GetConfig().TypeID.
			On(
				TypeIDNameSlice{
					TypeIDUvarint32,
					TypeIDUint32,
					TypeIDUint8,
				},
				func() {
					code := Empty()
					code.Comment("InstructionIDToName returns the name of the instruction given its ID.").Line()
					code.Func().Id("InstructionIDToName").
						Params(
							func() Code {
								switch GetConfig().TypeID {
								case TypeIDUvarint32, TypeIDUint32:
									return Id("id").Uint32()
								case TypeIDUint8:
									return Id("id").Uint8()
								}
								return nil
							}(),
						).
						Params(String()).
						BlockFunc(func(body *Group) {
							body.Switch(Id("id")).BlockFunc(func(switchBlock *Group) {
								for _, instruction := range idl.Instructions {
									insExportedName := ToCamel(instruction.Name)
									switchBlock.Case(Id("Instruction_" + insExportedName)).Line().Return(Lit(insExportedName))
								}
								switchBlock.Default().Line().Return(Lit(""))
							})

						})

					file.Add(code.Line())
				},
			).
			On(
				TypeIDNameSlice{
					TypeIDAnchor,
				},
				func() {
					code := Empty()
					code.Comment("InstructionIDToName returns the name of the instruction given its ID.").Line()
					code.Func().Id("InstructionIDToName").
						Params(Id("id").Qual(PkgBinary, "TypeID")).
						Params(String()).
						BlockFunc(func(body *Group) {
							body.Switch(Id("id")).BlockFunc(func(switchBlock *Group) {
								for _, instruction := range idl.Instructions {
									insExportedName := ToCamel(instruction.Name)
									switchBlock.Case(Id("Instruction_" + insExportedName)).Line().Return(Lit(insExportedName))
								}
								switchBlock.Default().Line().Return(Lit(""))
							})

						})
					file.Add(code.Line())
				},
			).
			On(
				TypeIDNameSlice{
					TypeIDNoType,
				},
				func() {
					// TODO
				},
			)
	}

	{
		{ // Base Instruction struct:
			code := Empty()
			code.Type().Id("Instruction").Struct(
				Qual(PkgBinary, "BaseVariant"),
			)
			file.Add(code.Line())
		}
		{
			// `EncodeToTree(parent treeout.Branches)` method
			code := Empty()
			code.Func().Parens(Id("inst").Op("*").Id("Instruction")).Id("EncodeToTree").
				Params(Id("parent").Qual(PkgTreeout, "Branches")).
				Params().
				BlockFunc(func(body *Group) {
					body.If(
						List(Id("enToTree"), Id("ok")).Op(":=").Id("inst").Dot("Impl").Op(".").Parens(Qual(PkgSolanaGoText, "EncodableToTree")).
							Op(";").
							Id("ok"),
					).Block(
						Id("enToTree").Dot("EncodeToTree").Call(Id("parent")),
					).Else().Block(
						Id("parent").Dot("Child").Call(Qual("github.com/davecgh/go-spew/spew", "Sdump").Call(Id("inst"))),
					)
				})
			file.Add(code.Line())
		}
		{
			// variant definitions for the decoder:
			GetConfig().TypeID.
				On(
					TypeIDNameSlice{
						TypeIDUvarint32,
						TypeIDUint32,
						TypeIDUint8,
					},
					func() {

						code := Empty()
						code.Var().Id("InstructionImplDef").Op("=").Qual(PkgBinary, "NewVariantDefinition").
							Parens(DoGroup(func(call *Group) {
								call.Line()

								switch GetConfig().TypeID {
								case TypeIDUvarint32:
									call.Qual(PkgBinary, "Uvarint32TypeIDEncoding").Op(",").Line()
								case TypeIDUint32:
									call.Qual(PkgBinary, "Uint32TypeIDEncoding").Op(",").Line()
								case TypeIDUint8:
									call.Qual(PkgBinary, "Uint8TypeIDEncoding").Op(",").Line()
								}

								call.Index().Qual(PkgBinary, "VariantType").
									BlockFunc(func(variantBlock *Group) {
										for _, instruction := range idl.Instructions {
											// NOTE: using `ToCamel` here:
											insName := ToCamel(instruction.Name)
											insExportedName := ToCamel(instruction.Name)
											variantBlock.Block(
												List(Lit(insName), Parens(Op("*").Id(insExportedName)).Parens(Nil())).Op(","),
											).Op(",")
										}
									}).Op(",").Line()
							}))
						file.Add(code.Line())

					},
				).
				On(
					TypeIDNameSlice{
						TypeIDAnchor,
					},
					func() {
						code := Empty()
						code.Var().Id("InstructionImplDef").Op("=").Qual(PkgBinary, "NewVariantDefinition").
							Parens(DoGroup(func(call *Group) {
								call.Line()
								call.Qual(PkgBinary, "AnchorTypeIDEncoding").Op(",").Line()

								call.Index().Qual(PkgBinary, "VariantType").
									BlockFunc(func(variantBlock *Group) {
										for _, instruction := range idl.Instructions {
											// NOTE: using `ToSnakeForSighash` here (necessary for sighash computing from instruction name)
											insName := sighash.ToSnakeForSighash(instruction.Name)
											insExportedName := ToCamel(instruction.Name)
											variantBlock.Block(
												List(Id("Name").Op(":").Lit(insName), Id("Type").Op(":").Parens(Op("*").Id(insExportedName)).Parens(Nil())).Op(","),
											).Op(",")
										}
									}).Op(",").Line()
							}))
						file.Add(code.Line())
					},
				).
				On(
					TypeIDNameSlice{
						TypeIDNoType,
					},
					func() {
						// TODO
					},
				)

		}
		{
			// method to return programID:
			code := Empty()
			code.Func().Parens(Id("inst").Op("*").Id("Instruction")).Id("ProgramID").Params().
				Parens(Qual(PkgSolanaGo, "PublicKey")).
				BlockFunc(func(body *Group) {
					body.Return(
						Id("ProgramID"),
					)
				})
			file.Add(code.Line())
		}
		{
			// method to return accounts:
			code := Empty()
			code.Func().Parens(Id("inst").Op("*").Id("Instruction")).Id("Accounts").Params().
				Parens(Id("out").Index().Op("*").Qual(PkgSolanaGo, "AccountMeta")).
				BlockFunc(func(body *Group) {
					body.Return(
						Id("inst").Dot("Impl").Op(".").Parens(Qual(PkgSolanaGo, "AccountsGettable")).Dot("GetAccounts").Call(),
					)
				})
			file.Add(code.Line())
		}
		{
			// `Data() ([]byte, error)` method:
			code := Empty()
			code.Func().Params(Id("inst").Op("*").Id("Instruction")).Id("Data").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Index().Byte()
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.Id("buf").Op(":=").New(Qual("bytes", "Buffer"))

					body.If(
						Err().Op(":=").Qual(PkgBinary, GetConfig().Encoding._NewEncoder()).Call(Id("buf")).Dot("Encode").Call(Id("inst")).
							Op(";").
							Err().Op("!=").Nil(),
					).Block(
						Return(List(Nil(), Qual("fmt", "Errorf").Call(Lit("unable to encode instruction: %w"), Err()))),
					)
					body.Return(Id("buf").Dot("Bytes").Call(), Nil())
				})
			file.Add(code.Line())
		}
		{
			// `TextEncode(encoder *text.Encoder, option *text.Option) error` method:
			code := Empty()
			code.Func().Params(Id("inst").Op("*").Id("Instruction")).Id("TextEncode").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("encoder").Op("*").Qual(PkgSolanaGoText, "Encoder")
						params.Id("option").Op("*").Qual(PkgSolanaGoText, "Option")
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.Return(Id("encoder").Dot("Encode").Call(Id("inst").Dot("Impl"), Id("option")))
				})
			file.Add(code.Line())
		}
		{
			// `UnmarshalWithDecoder(decoder *bin.Decoder) error` method:
			code := Empty()
			code.Func().Params(Id("inst").Op("*").Id("Instruction")).Id("UnmarshalWithDecoder").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("decoder").Op("*").Qual(PkgBinary, "Decoder")
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.Return(Id("inst").Dot("BaseVariant").Dot("UnmarshalBinaryVariant").Call(Id("decoder"), Id("InstructionImplDef")))
				})
			file.Add(code.Line())
		}
		{
			// `MarshalWithEncoder(encoder *bin.Encoder) error ` method:
			code := Empty()
			code.Func().Params(Id("inst").Op("*").Id("Instruction")).Id("MarshalWithEncoder").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("encoder").Op("*").Qual(PkgBinary, "Encoder")
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:

					GetConfig().TypeID.
						On(
							TypeIDNameSlice{
								TypeIDUvarint32,
								TypeIDUint32,
								TypeIDUint8,
							},
							func() {

								switch GetConfig().TypeID {
								case TypeIDUvarint32:
									body.Err().Op(":=").Id("encoder").Dot("WriteUVarInt").Call(Id("inst").Dot("TypeID").Dot("Uvarint32").Call())
								case TypeIDUint32:
									body.Err().Op(":=").Id("encoder").Dot("WriteUint32").Call(Id("inst").Dot("TypeID").Dot("Uint32").Call(), Qual("encoding/binary", "LittleEndian"))
								case TypeIDUint8:
									body.Err().Op(":=").Id("encoder").Dot("WriteUint8").Call(Id("inst").Dot("TypeID").Dot("Uint8").Call())
								}

							},
						).
						On(
							TypeIDNameSlice{
								TypeIDAnchor,
							},
							func() {
								body.Err().Op(":=").Id("encoder").Dot("WriteBytes").Call(Id("inst").Dot("TypeID").Dot("Bytes").Call(), False())
							},
						).
						On(
							TypeIDNameSlice{
								TypeIDNoType,
							},
							func() {
								// TODO
							},
						)

					body.If(
						Err().Op("!=").Nil(),
					).Block(
						Return(Qual("fmt", "Errorf").Call(Lit("unable to write variant type: %w"), Err())),
					)
					body.Return(Id("encoder").Dot("Encode").Call(Id("inst").Dot("Impl")))
				})
			file.Add(code.Line())
		}
		{
			// `registryDecodeInstruction` func:
			code := Empty()
			code.Func().Id("registryDecodeInstruction").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("accounts").Index().Op("*").Qual(PkgSolanaGo, "AccountMeta")
						params.Id("data").Index().Byte()
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Interface()
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:
					body.List(Id("inst"), Err()).Op(":=").Id("decodeInstruction").Call(Id("accounts"), Id("data"))

					body.If(
						Err().Op("!=").Nil(),
					).Block(
						Return(Nil(), Err()),
					)
					body.Return(Id("inst"), Nil())
				})
			file.Add(code.Line())
		}
		{
			// `DecodeInstruction` func:
			code := Empty()
			code.Func().Id("decodeInstruction").
				Params(
					ListFunc(func(params *Group) {
						// Parameters:
						params.Id("accounts").Index().Op("*").Qual(PkgSolanaGo, "AccountMeta")
						params.Id("data").Index().Byte()
					}),
				).
				Params(
					ListFunc(func(results *Group) {
						// Results:
						results.Op("*").Id("Instruction")
						results.Error()
					}),
				).
				BlockFunc(func(body *Group) {
					// Body:

					body.Id("inst").Op(":=").New(Id("Instruction"))

					body.If(
						Err().Op(":=").Qual(PkgBinary, GetConfig().Encoding._NewDecoder()).Call(Id("data")).Dot("Decode").Call(Id("inst")).
							Op(";").
							Err().Op("!=").Nil(),
					).Block(
						Return(
							Nil(),
							Qual("fmt", "Errorf").Call(Lit("unable to decode instruction: %w"), Err()),
						),
					)

					body.If(

						List(Id("v"), Id("ok")).Op(":=").Id("inst").Dot("Impl").Op(".").Parens(Qual(PkgSolanaGo, "AccountsSettable")).
							Op(";").
							Id("ok"),
					).BlockFunc(func(gr *Group) {
						gr.Err().Op(":=").Id("v").Dot("SetAccounts").Call(Id("accounts"))
						gr.If(Err().Op("!=").Nil()).Block(
							Return(
								Nil(),
								Qual("fmt", "Errorf").Call(Lit("unable to set accounts for instruction: %w"), Err()),
							),
						)
					})

					body.Return(Id("inst"), Nil())
				})
			file.Add(code.Line())
		}
	}

	return file, nil
}

// formatAccountAccessorName formats a name for a function that
// either gets or sets an account.
// If the RemoveAccountSuffix config flag is set, and the name already
// has an "Account" suffix, then another "Account" suffix is NOT added.
// E.g. ("Set", "Foo") => "SetFooAccount"
// E.g. ("Set", "BarAccount") => "SetBarAccount"
func formatAccountAccessorName(prefix, name string) string {
	endsWithAccount := strings.HasSuffix(strings.ToLower(name), "account")
	if !conf.RemoveAccountSuffix || !endsWithAccount {
		return prefix + name + "Account"
	}
	return prefix + name
}

func treeFindLongestNameFromFields(fields []IdlField) (ln int) {
	for _, v := range fields {
		if len(v.Name) > ln {
			ln = len(v.Name)
		}
	}
	return
}

func treeFindLongestNameFromAccounts(accounts IdlAccountItemSlice) (ln int) {
	accounts.Walk("", nil, nil, func(groupPath string, accountIndex int, parentGroup *IdlAccounts, ia *IdlAccount) bool {

		cleanedName := treeFormatAccountName(ia.Name)

		exportedAccountName := filepath.Join(groupPath, cleanedName)
		if len(exportedAccountName) > ln {
			ln = len(exportedAccountName)
		}

		return true
	})
	return
}

func treeFormatAccountName(name string) string {
	cleanedName := name
	if isSysVar(name) {
		cleanedName = strings.TrimSuffix(getSysVarName(name), "PublicKey")
	}
	if len(cleanedName) > len("account") {
		if strings.HasSuffix(cleanedName, "account") {
			cleanedName = strings.TrimSuffix(cleanedName, "account")
		} else if strings.HasSuffix(cleanedName, "Account") {
			cleanedName = strings.TrimSuffix(cleanedName, "Account")
		}
	}
	return cleanedName
}
