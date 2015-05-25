// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"camlistore.org/pkg/misc/gpgagent"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Code mostly taken from MIG; this is intended to cache the required GPG
// secrets using GPG agent prior to calling MIG.

func pgpCacheKeys(secpath string) error {
	fd, err := os.Open(secpath)
	if err != nil {
		return err
	}
	defer fd.Close()
	kr, err := openpgp.ReadKeyRing(fd)
	if err != nil {
		return err
	}
	var signer *openpgp.Entity
	found := false
	for _, entity := range kr {
		if entity.PrivateKey == nil {
			return errors.New("secring contains entity without private key data")
		}
		fingerprint := strings.ToUpper(hex.EncodeToString(entity.PrivateKey.PublicKey.Fingerprint[:]))
		if config.Main.KeyID == fingerprint {
			signer = entity
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("signer '%v' not found", config.Main.KeyID)
	}
	if !signer.PrivateKey.Encrypted {
		return nil
	}

	return decryptEntity(signer)
}

func decryptEntity(s *openpgp.Entity) (err error) {
	pubk := &s.PrivateKey.PublicKey
	desc := fmt.Sprintf("Need to cache GPG key %v for signing", pubk.KeyIdShortString())

	conn, err := gpgagent.NewConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	req := &gpgagent.PassphraseRequest{
		CacheKey: "mig:pgpsign:" + pubk.KeyIdShortString(),
		Prompt:   "Passphrase",
		Desc:     desc,
	}
	for tries := 0; tries < 3; tries++ {
		var pass string
		pass, err = conn.GetPassphrase(req)
		if err != nil {
			return errors.New("decryption failed")
		}
		err = s.PrivateKey.Decrypt([]byte(pass))
		if err == nil {
			return err
		}
		req.Error = "Passphrase failed to decrypt"
		conn.RemoveFromCache(req.CacheKey)
		continue
	}
	return errors.New("decryption failed too many times")
}
