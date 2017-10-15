package proj2


// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.


import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"
	
	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// For the useful little debug printing function
	"fmt"
	"time"
	"os"
	"strings"

	// I/O
	"io"
	
	// Want to import errors
	"errors"
	
	// These are imported for the structure definitions.  You MUST
	// not actually call the functions however!!!
	// You should ONLY call the cryptographic functions in the
	// userlib, as for testing we may add monitoring functions.
	// IF you call functions in here directly, YOU WILL LOSE POINTS
	// EVEN IF YOUR CODE IS CORRECT!!!!!
	"crypto/rsa"
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings(){
	// Creates a random UUID
	f := uuid.New()
	debugMsg("UUID as string:%v", f.String())
	
	// Example of writing over a byte of f
	f[0] = 10
	debugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	debugMsg("The hex: %v", h)
	
	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d,_ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key,_ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range(ret){
		ret[x] = data[x]
	}
	return
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte){
	data = make([]byte, bytes)
	if _, err := io.ReadFull(userlib.Reader, data); err != nil {
		panic(err)
	}
	return
}

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func debugMsg(format string, args ...interface{}) {
	if DebugPrint{
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg + strings.Trim(format, "\r\n ") + "\n", args...)
	}
}


// The structure definition for a user record
type User struct {
	Username string
	Password string
	RSAPrivKey *rsa.PrivateKey
	HMACKey []byte
	EncryptKey []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// The structure definition for a header file
type Header struct {
	Filename string
	MerkleRoot string
	EncryptKey []byte
	HMACKey []byte
	PrevRoot []byte
}

//The structure definition for a merkle root file
type MerkleRoot struct {
	Root []byte
	DataBlocks []string
}

//The structure definiiton for a data block file
type DataBlock struct {
	Bytes []byte
}



// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//TODO: Double check filenaming scheme
func InitUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	privkey, err := userlib.GenerateRSAKey()
	if err != nil {
		panic(err)
	}
	keys := userlib.PBKDF2Key(password, username, userlib.HashSize + userlib.AESKeySize)
	hmac_key, encrypt_key := keys[0:userlib.HashSize], keys[userlib.HashSize:]
	userdata = User{username, password, privkey, hmac_key, encrypt_key}
	append(username, password...)
	if err := EncryptAndStore(username, hmac_key, encrypt_key, &userdata); err != nil {
		panic("Data was not able to be stored")
	}
	userlib.KeystoreSet(username, privkey.PublicKey)
	return &userdata, err
}



// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

//TODO: Return an appropriate error message. Implement specificity of checks Fix || usage
func GetUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	keys := userlib.PBKDF2Key(password, username, userlib.HashSize + userlib.AESKeySize)
	hmac_key, encrypt_key := keys[0:userlib.HashSize], keys[userlib.HashSize:]
	secure_filename := HMAC(hmac_key || username || password)
	if err := VerifyAndDecrypt(secure_filename, hmac_key, encrypt_key, &userdata); err != nil {
		panic("Unable to load user struct file")
	}
	return &userdata, err
}



// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!

func (userdata *User) StoreFile(filename string, data []byte) {
	file_encrypt_key, file_hmac_key := randomBytes(userlib.AESKeySize), randomBytes(userlib.BlockSize)
	datablock_name, datablock := GenerateHMAC(hmac_key, randomBytes(32)), DataBlock{data}
	if err := EncryptAndStore(datablock_name, file_hmac_key, file_encrypt_key, &datablock); err != nil {
		panic("Data block was not stored")
	}
	blocks := [1]DataBlock{datablock}
	root := ComputeMerkleRoot(blocks)
	merkleroot_name, merkleroot := GenerateHMAC(file_hmac_key, randomBytes(32)),  MerkleRoot{root, blocks}
	if err := EncryptAndStore(merkleroot_name, file_hmac_key, file_encrypt_key, &merkleroot); err != nil {
		panic("Merkle root was not stored. Datablock deleted")
	}
	header := Header{filename, merkleroot_name, file_encrypt_key, file_hmac_key, root}
	header_name := GenerateHMAC(userdata.HMACKey, userdata.Username || userdata.Password || filename) 
	if err := EncryptAndStore(header_name, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Header was not stored")
	}
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	//Load file is a helper that returns byte blocks
	//TODO: check if data is intact
	var header Header; var merkleroot MerkleRoot
	header_name := GenerateHMAC(userdata.HMACKey, userdata.Username || userdata.Password || filename) 
	if err := VerifyAndDecrypt(header_name, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Unable to load Header file")
	}
	data_blocks, merkle_root, err := LoadDataBlocks(filename, userdata)
	if err != nil {
		panic("Datablocks unable to be loaded")
	}
	append(data_blocks, data)
	ComputeMerkleRoot(data_blocks)

	//TODO: add data to the files modularize EncrypteAndStore
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

//TODO: what is the format of the output data
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	var data []byte
	data_blocks, merkle_root, err := LoadDataBlocks(filename, userdata)
	if err != nil {
		panic("Data was unable to be loaded in helper")
	}
	if err := VerifyMerkleRoot(data, merkle_root); err == false {
		panic("Merkle roots do not match")
	}
	for _, v := data_blocks {
		append(data, v)
	}
 	return data, err 
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	MerkleRoot string
	EncryptKey []byte
	HMACKey []byte
	PrevRoot []byte
}


// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

//TODO figure out what HMAC key to use to encrypt the merkle root
func (userdata *User) ShareFile(filename string, recipient string)(
	msgid string, err error){
	header_name := GenerateHMAC(userdata.HMACKey, userdata.userdataname || userdata.Password || filename)
	ciphertext, err := userlib.DatastoreGet(header_name)
	if err != nil {
		panix("Error retrieving the file")
	}
	encrypted_header, header_hmac := ciphertext[:len(ciphertext) - userlib.BlockSize], ciphertext[len(ciphertext) - userlib.BlockSize:]
	if !VerifyHMAC(userdata.HMACKey, encrypted_header, header_hmac) {
		panic("Encrypted text does not match HMAC")
	}
	plaintext := DecryptData(userdata.EncryptKey, encrypted_header)
	var header Header 
	err := json.Unmarshal(plaintext, &header)
	if err != nil {
		panic("Unable to load decrypted cyphertext")
	}
	ciphertext, err := userlib.DatastoreGet(header.MerkleRoot)
	if err != nil {
		panic("Unable to load Merkle Root file")
	}
	encrypted_merkle, merkle_hmac := ciphertext[:len(ciphertext) - userlib.BlockSize], ciphertext[len(ciphertext) - userlib.BlockSize:]
	if !VerifyHMAC(Header.HMACKey, encrypted_merkle, merkle_hmac) {
		panic("Encrypted merkle does not match HMAC")
	}
	plaintext := DecryptData(Header.EncryptKey, encrypted_merkle)
	var merkle MerkleRoot
	err := json.Unmarshal(plaintext,&merkle)
	if err != nil {
		panic("Unable to load decrypted ciphertext")
	}
	recipient_key := userlib.KeystoreGet(recipient)
	rsaencrypted_merkle, err := userlib.RSAEncrypt(recipient_key, merkle)
	if err != nil {
		panic("Unable to encrypt merkle")
	}
	rsaencrypted_filekey, err := userlib.RSAEncrypt(recipient_key, header.EncryptKey)
	if err != nil {
		panic("Unable to encrypt file encryption key")
	}
	rsaencrypted_filehmac, err := userlib.RSAEncrypt(recipient_key, header.HMACKey)
	if err != nil {
		panic("Unable to encrypt file HMAC")
	}
	rsaencrypted_prev, err := userlib.RSAEncrypt(recipient_key, header.PrevRoot)
	if err != nil {
		panic("Unable to encrypt previous root")
	}
	var record sharingRecord
	record.EncryptKey := rsaencrypted_filekey
	record.HMACKey := rsaencrypted_filehmac
	record.MerkleRoot := rsaencrypted_merkle
	record.PrevRoot := rsaencrypted_merkle
	HMACRecord := GenerateHMAC(header.HMACKey, record)
	append(record, HMACRecord...) 
	msgid := randomBytes(16)
	err := userlib.DatastoreSet(msgid, record)
	return msgid, err
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.

//still needs to use a verify HMAC
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	var header Header
	ciphertext, err := userlib.DatastoreGet(msgid)
	if err != nil {
		panic("Unable to retrieve message")
	}
	header.Filename = filename
	var share sharingRecord
	err := json.Unmarshal(ciphertext, &share)
	if err != nil {
		panic("Unable to load ciphertext")
	}
	header.MerkleRoot, err := userlib.RSADecrypt(userdata.RSAPrivKey, share.MerkleRoot, [])
	if err != nil {
		panic("Unable to decrypt MerkleRoot")
	}
	header.HMACKey, err := userlib.RSADecrypt(userdata.RSAPrivKey, share.HMACKey, [])
	if err != nil {
		panic("Unable to decrypt HMACKey")
	}
	header.PrevRoot, err := userlib.RSADecrypt(userdata.RSAPrivKey, share.PrevRoot, [])
	if err != nil {
		panic("Unable to decrypt PrevRoot")
	}
	header.EncryptKey, err := userlib.RSADecrypt(userdata.RSAPrivKey, share.EncryptKey, [])
	if err != nil {bbb
		panic("Unable to decrypt EncryptKey")
	}
	err := EncryptAndStore(filename, userdata.HMACKey, userdata.EncryptKey, &header)
	return err
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	data_blocks, merkle_root, header, err := LoadDataBlocks(filename, userdata)
	copy_data_blocks := data_blocks
	if err != nil {
		panic("Data was unable to be loaded in helper")
	}
	if err := VerifyMerkleRoot(data_blocks, merkle_root); err == false {
		panic("Merkle roots do not match")
	}
	for _, v := data_blocks {
		delete(v)
	}
	delete(merkle_root)
	delete(header)
	userdata.StoreFile(filename, copy_data_blocks[0])
	var err_return error
	for i := 1, i < len(copy_data_blocks), i++ {
		err := userdata.AppendFile(filename, copy_data_blocks[1])
		if err != nil {
			panic(err)
			err_return := err
		}
	}
	return err_return
}

// Helper function encrypts data and returns ciphertext
func EncryptData(key byte[], plaintext []byte) (byte[]) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, userlib.BlockSize+len(plaintext))
	iv := ciphertext[userlib.BlockSize]
	if _, err := io.ReadFull(randomBytes(userlib.BlockSize), iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[userlib.BlockSize:], plaintext)
	return ciphertext
}

// Helpexr function verifies HMAC on ciphertext
func VerifyHMAC(key byte[], data byte[], old_mac byte[]) (bool) {
	new_mac := GenerateHMAC(key, data)
	return Equal(new_mac, old_mac)
}

// Helper function decrypts data and returns plaintext
func DecryptData(key byte[], ciphertext byte[]) (byte[]) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < userlib.BlockSize {
		//TODO: Handle this error appropriately
		panic("ciphertext too short")
	}
	iv := ciphertext[:userlib.BlockSize]
	ciphertext = ciphertext[userlib.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	return stream.XORKeyStream(ciphertext, ciphertext)
}

// Helper function takes data and returns MAC. Data must be encrypted.
func GenerateHMAC(key byte[], data byte[]) (byte[]) {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	mac_data := mac.Sum(nil)
	return mac_data
}

//Helper function computes the merkle root of a set of leaves in a merkle tree
func ComputeMerkleRoot(byte[][] leaves) (byte[]) {
	for len(leaves) > 1 {
		hashes, iter_count := make(byte[][]), len(leaves) / 2 + len(leaves) % 2
		for (iter_count > 0) {
			if len(leaves) == 1 {
				first, second, leaves := leaves[0], nil, leaves[1:]
			} else {
				first, second, leaves := leaves[0], leaves[1], leaves[2:]
			}
			hash := userlib.NewSHA256()
			hash.write(first)
			hash.Sum(nil)
			append(hashes, hash)
		}
		leaves = hashes
	}
	return leaves[0]
}

//Helper function that marshals, encrypts, and stores file on the datastore
func EncryptAndStore(filename []byte, hmac_key []byte, encrypt_key []byte, v interface{}) (err error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic("Data was not able to be marshalled")
	}
	encrypted_data := EncryptData(encrypt_key, bytes)
	hmac := GenerateHMAC(hmac_key, encrypted_data)
	append(encrypted_data, hmac...)
	userlib.DatastoreSet(filename, encrypted_data)
	return err
}

//Helper function that retrieves, verifies, decrypts, and unmarshals the stored file
func VerifyAndDecrypt(filename []byte, hmac_key []byte, encrypt_key []byte, v interface{}) (err error) {
	ciphertext, err := userlib.DatastoreGet(filename)
	if err != nil {
		panic("Error retrieving the file")
	}
	encrypted_data, hmac := ciphertext[:len(ciphertext) - userlib.BlockSize], ciphertext[len(ciphertext) - userlib.BlockSize:]
	if !VerifyHMAC(hmac_key, encrypted_data, hmac) {
		panic("Encrypted text does not match HMAC")
	}
	plaintext := DecryptData(encrypt_key, encrypted_data)
	err := json.Unmarshal(plaintext, v)
	if err != nil {
		panic("Unable to load decrypted ciphertext")
	}
	return err
}

// helper function that loads all blocks of data from a file
func LoadDataBlocks(filename string, userdata *User) ([][]byte, []byte, err error) {
	var header Header; var merkle_root MerkleRoot; var block DataBlock
	secure_filename := GenerateHMAC(userdata.HMACKey, userdata.Username || userdata.Password || filename) 
	
	if err := VerifyAndDecrypt(secure_filename, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Unable to load Header file")
	}
	if err := VerifyAndDecrypt(header.MerkleRoot, header.HMACKey, header.EncryptKey, &merkle_root); err != nil {
		panic("Unable to load Merkle Root file")
	}
	data_blocks := make(byte[][])
	for _, v := range merkle.DataBlocks {
		if 	err := VerifyAndDecrypt(v, header.HMACKey, header.EncryptKey, &block); err != nil {
			panic("Unable to load Merkle Root file")
		}
		append(data_blocks, block.Bytes)
	}
	return data_blocks, header.MerkleRoot, err
}

func LoadDataBlocksHeader(filename string, userdata *User) ([][]byte, []byte, err error) {
	var header Header; var merkle_root MerkleRoot; var block DataBlock
	secure_filename := GenerateHMAC(userdata.HMACKey, userdata.Username || userdata.Password || filename) 
	
	if err := VerifyAndDecrypt(secure_filename, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Unable to load Header file")
	}
	if err := VerifyAndDecrypt(header.MerkleRoot, header.HMACKey, header.EncryptKey, &merkle_root); err != nil {
		panic("Unable to load Merkle Root file")
	}
	data_blocks := make(byte[][])
	for _, v := range merkle.DataBlocks {
		if 	err := VerifyAndDecrypt(v, header.HMACKey, header.EncryptKey, &block); err != nil {
			panic("Unable to load Merkle Root file")
		}
		append(data_blocks, block.Bytes)
	}
	return data_blocks, header.MerkleRoot,, header, err
}
func VerifyMerkleRoot(blocks [][]byte, prev []byte) (bool) {
	new_root := ComputeMerkleRoot(data_blocks)
	if prevRoot != new_root {
		panic("Merkle roots are incorrrect; changes were made to the file")
		return false
	}
	return true
}


