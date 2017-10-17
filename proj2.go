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
	"os"
	"strings"
	"time"

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
func someUsefulThings() {
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
	d, _ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte) {
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
	if DebugPrint {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// The structure definition for a user record
type User struct {
	Username   string
	Password   string
	RSAPrivKey *rsa.PrivateKey
	HMACKey    []byte
	EncryptKey []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// The structure definition for a header file
type Header struct {
	Filename   string
	MerkleRoot []byte
	EncryptKey []byte
	HMACKey    []byte
	PrevRoot   []byte
}

//The structure definition for a merkle root file
type MerkleRoot struct {
	Root       []byte
	DataBlocks [][]byte
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
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	privkey, err := userlib.GenerateRSAKey()
	if err != nil {
		panic(err)
	}
	keys := userlib.PBKDF2Key([]byte(password), []byte(username), userlib.HashSize+userlib.AESKeySize)
	hmac_key, encrypt_key := keys[0:userlib.HashSize], keys[userlib.HashSize:]
	userdata = User{username, password, privkey, hmac_key, encrypt_key}
	filename := username + password
	if err := EncryptAndStore([]byte(filename), hmac_key, encrypt_key, &userdata); err != nil {
		panic("Data was not able to be stored")
	}
	userlib.KeystoreSet(username, privkey.PublicKey)
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

//TODO: Return an appropriate error message. Implement specificity of checks Fix || usage
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	keys := userlib.PBKDF2Key([]byte(password), []byte(username), userlib.HashSize+userlib.AESKeySize)
	hmac_key, encrypt_key := keys[0:userlib.HashSize], keys[userlib.HashSize:]
	if err := VerifyAndDecrypt([]byte(username+password), hmac_key, encrypt_key, &userdata); err != nil {
		panic("Unable to load user struct file")
	}
	return &userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!

func (userdata *User) StoreFile(filename string, data []byte) {
	file_encrypt_key, file_hmac_key := randomBytes(userlib.AESKeySize), randomBytes(userlib.HashSize)
	datablock_name, datablock := randomBytes(userlib.HashSize), DataBlock{data}
	if err := EncryptAndStore(datablock_name, file_hmac_key, file_encrypt_key, &datablock); err != nil {
		panic("Data block was not stored")
	}
	blocks := [][]byte{data}
	block_names := make([][]byte, 0)
	root := ComputeMerkleRoot(blocks)
	merkleroot_name := randomBytes(userlib.HashSize)
	block_names = append(block_names, datablock_name)
	merkleroot := MerkleRoot{root, block_names}
	if err := EncryptAndStore(merkleroot_name, file_hmac_key, file_encrypt_key, &merkleroot); err != nil {
		panic("Merkle root was not stored. Datablock deleted")
	}
	header := Header{filename, merkleroot_name, file_encrypt_key, file_hmac_key, root}
	header_name := []byte(userdata.Username + userdata.Password + filename)
	if err := EncryptAndStore(header_name, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Header was not stored")
	}
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//Load file is a helper that returns byte blocks
	//TODO: check if data is intact
	var header Header
	var merkleroot MerkleRoot
	var data_block DataBlock
	header_name := []byte(userdata.Username + userdata.Password + filename)
	if err := VerifyAndDecrypt(header_name, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Unable to load Header file")
	}
	if err := VerifyAndDecrypt(header.MerkleRoot, header.HMACKey, header.EncryptKey, &merkleroot); err != nil {
		panic("Unable to load Merkle file file")
	}
	data_blocks, err := LoadDataBlocks(filename, userdata)
	if err != nil {
		panic("Datablocks unable to be loaded")
	}

	datablock_name := randomBytes(userlib.HashSize)
	data_block = DataBlock{data}

	data_blocks = append(data_blocks, data)
	new_root := ComputeMerkleRoot(data_blocks)
	merkleroot_name := header.MerkleRoot
	merkleroot = MerkleRoot{new_root, append(merkleroot.DataBlocks, datablock_name)}

	if err := EncryptAndStore(datablock_name, header.HMACKey, header.EncryptKey, &data_block); err != nil {
		panic("Data was not stored")
	}
	if err := EncryptAndStore(merkleroot_name, header.HMACKey, header.EncryptKey, &merkleroot); err != nil {
		panic("Merkle root was not stored")
	}
	header = Header{filename, merkleroot_name, header.EncryptKey, header.HMACKey, new_root}
	header_name = []byte(userdata.Username + userdata.Password + filename)
	if err := EncryptAndStore(header_name, userdata.HMACKey, userdata.EncryptKey, &header); err != nil {
		panic("Header was not stored")
	}
	//TODO: add data to the files modularize EncrypteAndStore
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

//TODO: what is the format of the output data
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	data_blocks, err := LoadDataBlocks(filename, userdata)

	if err != nil {
		panic("Data was unable to be loaded in helper")
	}
	for _, v := range data_blocks {
		data = append(data, v...)
	}
	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	MerkleRoot []byte
	EncryptKey []byte
	HMACKey    []byte
	PrevRoot   []byte
	RSASign    []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	var header Header
	if err := VerifyAndDecrypt(
		[]byte(userdata.Username+userdata.Password+filename),
		userdata.HMACKey,
		userdata.EncryptKey,
		&header); err != nil {
		panic("Unable to load Header file")
	}
	recipient_key, ok := userlib.KeystoreGet(recipient)
	if !ok {
		panic("Unable to load recipient's key from keystore")
	}
	rsaencrypted_merkle, err := userlib.RSAEncrypt(&recipient_key, header.MerkleRoot, []byte(recipient))
	if err != nil {
		panic("Unable to encrypt merkle")
	}
	rsaencrypted_filekey, err := userlib.RSAEncrypt(&recipient_key, header.EncryptKey, []byte(recipient))
	if err != nil {
		panic("Unable to encrypt file encryption key")
	}
	rsaencrypted_filehmac, err := userlib.RSAEncrypt(&recipient_key, header.HMACKey, []byte(recipient))
	if err != nil {
		panic("Unable to encrypt file HMAC")
	}
	rsaencrypted_prev, err := userlib.RSAEncrypt(&recipient_key, header.PrevRoot, []byte(recipient))
	if err != nil {
		panic("Unable to encrypt previous root")
	}
	var record sharingRecord
	record.EncryptKey = rsaencrypted_filekey
	record.HMACKey = rsaencrypted_filehmac
	record.MerkleRoot = rsaencrypted_merkle
	record.PrevRoot = rsaencrypted_prev
	enc, hmac, merk, prev := bytesToUUID(rsaencrypted_filekey), bytesToUUID(rsaencrypted_filehmac), bytesToUUID(rsaencrypted_merkle), bytesToUUID(rsaencrypted_prev)
	rsastring := []byte(enc.String() + hmac.String() + merk.String() + prev.String())
	RSARecord, err := userlib.RSASign(userdata.RSAPrivKey, rsastring)
	if err != nil {
		panic("Unable to sign record")
	}
	record.RSASign = RSARecord
	msgbytes := randomBytes(16)
	msgiduuid := bytesToUUID(msgbytes)
	msgid = msgiduuid.String()
	bytes, err := json.Marshal(record)
	if err != nil {
		panic("unable to marshal the data")
	}
	userlib.DatastoreSet(msgid, bytes)
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
	var sharing sharingRecord
	ciphertext, err := userlib.DatastoreGet(msgid)
	if !err {
		panic("Unable to retrieve message")
	}
	header.Filename = filename
	err1 := json.Unmarshal(ciphertext, &sharing)
	if err1 != nil {
		panic("Unable to load ciphertext")
	}

	PublicKey, _ := userlib.KeystoreGet(sender)
	enc, hmac, merk, prev := bytesToUUID(sharing.EncryptKey), bytesToUUID(sharing.HMACKey), bytesToUUID(sharing.MerkleRoot), bytesToUUID(sharing.PrevRoot)
	rsastring := []byte(enc.String() + hmac.String() + merk.String() + prev.String())

	err1 = userlib.RSAVerify(&PublicKey, rsastring, sharing.RSASign)

	if err1 != nil {
		panic("RSA signature not verified")
	}
	header.MerkleRoot, err1 = userlib.RSADecrypt(userdata.RSAPrivKey, sharing.MerkleRoot, []byte(userdata.Username))
	if err1 != nil {
		panic("Unable to decrypt MerkleRoot")
	}
	header.HMACKey, err1 = userlib.RSADecrypt(userdata.RSAPrivKey, sharing.HMACKey, []byte(userdata.Username))
	if err1 != nil {
		panic("Unable to decrypt HMACKey")
	}
	header.PrevRoot, err1 = userlib.RSADecrypt(userdata.RSAPrivKey, sharing.PrevRoot, []byte(userdata.Username))
	if err1 != nil {
		panic("Unable to decrypt PrevRoot")
	}
	header.EncryptKey, err1 = userlib.RSADecrypt(userdata.RSAPrivKey, sharing.EncryptKey, []byte(userdata.Username))
	if err1 != nil {
		panic("Unable to decrypt EncryptKey")
	}
	err1 = EncryptAndStore([]byte(userdata.Username+userdata.Password+filename), userdata.HMACKey, userdata.EncryptKey, &header)
	if err1 != nil {
		panic("Unable to encrypt and store")
	}
	return err1
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	data_blocks, header, err := LoadDataBlocksHeader(filename, userdata)
	var copy_data_blocks [][]byte
	i := 0
	for i < len(data_blocks) {
		copy_data_blocks[i] = make([]byte, len(data_blocks[i]))
		copy(copy_data_blocks[i], data_blocks[i])
	}
	if err != nil {
		panic("Data was unable to be loaded in helper")
	}
	if err := VerifyMerkleRoot(data_blocks, header.PrevRoot); err == false {
		panic("Merkle roots do not match")
	}
	data_blocks = nil
	header = Header{}
	userdata.StoreFile(filename, copy_data_blocks[0])
	i = 1
	for i < len(copy_data_blocks) {
		err := userdata.AppendFile(filename, copy_data_blocks[i])
		if err != nil {
			panic(err)
		}
	}
	return err
}

// Helper function encrypts data and returns ciphertext
func EncryptData(key []byte, plaintext []byte) []byte {
	ciphertext := make([]byte, userlib.BlockSize+len(plaintext))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(plaintext))
	return ciphertext
}

// Helper function verifies HMAC on ciphertext
func VerifyHMAC(key []byte, data []byte, old_mac []byte) bool {
	new_mac := GenerateHMAC(key, data)
	return userlib.Equal(new_mac, old_mac)
}

// Helper function decrypts data and returns plaintext
func DecryptData(key []byte, ciphertext []byte) []byte {
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(key, iv)
	// Yes you can do this in-place
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	return ciphertext[userlib.BlockSize:]
}

// Helper function takes data and returns MAC. Data must be encrypted.
func GenerateHMAC(key []byte, data []byte) []byte {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	mac_data := mac.Sum(nil)
	return mac_data
}

//Helper function computes the merkle root of a set of leaves in a merkle tree
func ComputeMerkleRoot(leaves [][]byte) []byte {
	for i, _ := range leaves {
		leaves[i] = ComputeShaHash(leaves[i])
	}
	for len(leaves) > 1 {
		hashes, iter_count := make([][]byte, 0), len(leaves)/2+len(leaves)%2
		var first []byte
		var second []byte
		for iter_count > 0 {
			if len(leaves) == 1 {
				first, second, leaves = leaves[0], nil, leaves[1:]
			} else {
				first, second, leaves = leaves[0], leaves[1], leaves[2:]
			}
			first = append(first, second...)
			hashes = append(hashes, ComputeShaHash(first))
			iter_count -= 1
		}
		leaves = hashes
	}
	return leaves[0]
}

func ComputeShaHash(data []byte) (scramble []byte) {
	hash := userlib.NewSHA256()
	hash.Write(data)
	return hash.Sum(nil)
}

//Helper function that marshals, encrypts, and stores file on the datastore
func EncryptAndStore(filename []byte, hmac_key []byte, encrypt_key []byte, v interface{}) (err error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic("Data was not able to be marshalled")
	}
	encrypted_data := EncryptData(encrypt_key, bytes)
	hmac := GenerateHMAC(hmac_key, encrypted_data)
	encrypted_data = append(encrypted_data, hmac...)
	secure_filename := GenerateHMAC(hmac_key, []byte(filename))
	userlib.DatastoreSet(string(secure_filename), encrypted_data)
	return err
}

//Helper function that retrieves, verifies, decrypts, and unmarshals the stored file
func VerifyAndDecrypt(filename []byte, hmac_key []byte, encrypt_key []byte, v interface{}) (err error) {

	secure_filename := GenerateHMAC(hmac_key, []byte(filename))
	ciphertext, success := userlib.DatastoreGet(string(secure_filename))
	if success != true {
		panic("Error retrieving the file")
	}
	encrypted_data, hmac := make([]byte, len(ciphertext)-userlib.HashSize), make([]byte, userlib.HashSize)
	copy(encrypted_data, ciphertext[:len(ciphertext)-userlib.HashSize])
	copy(hmac, ciphertext[len(ciphertext)-userlib.HashSize:])
	if !VerifyHMAC(hmac_key, encrypted_data, hmac) {
		panic("Encrypted text does not match HMAC")
	}
	plaintext := DecryptData(encrypt_key, encrypted_data)
	err = json.Unmarshal(plaintext, v)
	if err != nil {
		panic("Unable to load decrypted ciphertext")
	}
	return err
}

// helper function that loads all blocks of data from a file
func LoadDataBlocks(filename string, userdata *User) (data_blocks [][]byte, err error) {
	var header Header
	var merkle_root MerkleRoot
	var block DataBlock

	if err := VerifyAndDecrypt(
		[]byte(userdata.Username+userdata.Password+filename),
		userdata.HMACKey,
		userdata.EncryptKey,
		&header); err != nil {
		panic("Unable to load Header file")
	}
	if err := VerifyAndDecrypt(header.MerkleRoot, header.HMACKey, header.EncryptKey, &merkle_root); err != nil {
		panic("Unable to load Merkle Root file")
	}
	data_blocks = make([][]byte, 0)
	for _, v := range merkle_root.DataBlocks {
		if err = VerifyAndDecrypt(v, header.HMACKey, header.EncryptKey, &block); err != nil {
			panic("Unable to load Merkle Root file")
		}
		data_blocks = append(data_blocks, block.Bytes)

	}
	merkle_leaves := make([][]byte, len(data_blocks))
	copy(merkle_leaves, data_blocks)

	if success := VerifyMerkleRoot(merkle_leaves, header.PrevRoot); success == false {
		panic("Merkle roots are incorrect")
	}
	return data_blocks, err
}

func LoadDataBlocksHeader(filename string, userdata *User) (data_blocks [][]byte, header Header, err error) {
	var merkle_root MerkleRoot
	var block DataBlock

	if err := VerifyAndDecrypt(
		[]byte(userdata.Username+userdata.Password+filename),
		userdata.HMACKey,
		userdata.EncryptKey,
		&header); err != nil {
		panic("Unable to load Header file")
	}
	if err := VerifyAndDecrypt(header.MerkleRoot, header.HMACKey, header.EncryptKey, &merkle_root); err != nil {
		panic("Unable to load Merkle Root file")
	}
	data_blocks = make([][]byte, 0)
	for _, v := range merkle_root.DataBlocks {
		if err = VerifyAndDecrypt(v, header.HMACKey, header.EncryptKey, &block); err != nil {
			panic("Unable to load Merkle Root file")
		}
		data_blocks = append(data_blocks, block.Bytes)

	}
	merkle_leaves := make([][]byte, len(data_blocks))
	copy(merkle_leaves, data_blocks)

	if success := VerifyMerkleRoot(merkle_leaves, header.PrevRoot); success == false {
		panic("Merkle roots are incorrect")
	}
	return data_blocks, header, err
}
func VerifyMerkleRoot(blocks [][]byte, prev []byte) bool {
	new_root := ComputeMerkleRoot(blocks)
	if !userlib.Equal(prev, new_root) {
		panic("Merkle roots are incorrrect; changes were made to the file")
		return false
	}
	return true
}
