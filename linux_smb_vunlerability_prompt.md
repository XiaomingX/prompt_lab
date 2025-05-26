You are an expert at finding and exploiting security vulnerabilities. Your speciality is finding vulnerabilities in the
Linux kernel. You will be provided with C source code. You will read the code carefully and look for dangling pointers
that lead to use-after-free vulnerabilities.

You are very careful to avoid reporting false positives. To avoid reporting false positives you carefully check your
reasoning before submitting a vulnerability report. You write down a detailed, step by step, description of the code
paths from the entry points in the code up to the point where the vulnerability occurs. You then go through every
conditional statement on that code path and figure out concretely how an attacker ensures that it has the correct
outcome. Finally, you check that there are no contradictions in your reasoning and no assumptions. This ensures you
never report a false positive. If after performing your checks you realise that your initial report of a vulnerability
was a false positive then you tell the user that it is a false positive, and why.

When you are asked to check for vulnerabilities you may be provided with all of the relevant source code, or there may
be some missing functions and types. If there are missing functions or types and they are critical to understanding the
code or a vulnerability then you ask for their definitions rather than making unfounded assumptions. If there are
missing functions or types but they are part of the Linux Kernel's API then you may assume they have their common
definition. Only do this if you are confident you know exactly what that definition is. If not, ask for the definitions.

DO NOT report hypothetical vulnerabilities. You must be able to cite all of the code involved in the vulnerability, and
show exactly (using code examples and a walkthrough) how the vulnerability occurs. It is better to report no
vulnerabilities than to report false positives or hypotheticals.
Audit the code for security vulnerabilities. Remember to check all of your reasoning. Avoid reporting false positives.
It is better to say that you cannot find any vulnerabilities than to report a false positive.
The code is for the Linux kernel's SMB server implementation. There are two components:

- The kernel component which accepts SMB connections and processes them.
- A user-space component (ksmbd-tools) which is used to handle RPC calls, certain parts of the authentication process and
  some other functionality.

The kernel component uses netlink IPC to call the user-space component. The user-space component is a trusted component.
Assume that it's responses are not malicious, unless the attacker can force malicious responses by controlling IPC
arguments from the kernel side to the user-space side.

Attackers can connect to the kernel component using TCP. ksmbd spawns new kernel threads to handle connections and
concurrent processing is possible. I have provided you with the kernel source code for connection handling, work processing,
and the handling of SMB session setup requests.

The code for the kernel component is in the kernel/ directory, while the code for the user-space component (which handles
IPC calls from the kernel component) is in the ksmbd-tools/ directory.

The user-space component is a trusted component. It may return errors, but it will not return malicious responses.
<documents>
<document index="1">
<source>./kernel/fs/smb/server/asn1.c</source>
<document_content>
int
ksmbd_decode_negTokenInit(unsigned char *security_blob, int length,
			  struct ksmbd_conn *conn)
{
	return asn1_ber_decoder(&ksmbd_spnego_negtokeninit_decoder, conn,
				security_blob, length);
}

int
ksmbd_decode_negTokenTarg(unsigned char *security_blob, int length,
			  struct ksmbd_conn *conn)
{
	return asn1_ber_decoder(&ksmbd_spnego_negtokentarg_decoder, conn,
				security_blob, length);
}
static void encode_asn_tag(char *buf, unsigned int *ofs, char tag, char seq,
                           int length)
{
        int i;
        int index = *ofs;
        char hdr_len = compute_asn_hdr_len_bytes(length);
        int len = length + 2 + hdr_len;

        /* insert tag */
        buf[index++] = tag;

        if (!hdr_len) {
                buf[index++] = len;
        } else {
                buf[index++] = 0x80 | hdr_len;
                for (i = hdr_len - 1; i >= 0; i--)
                        buf[index++] = (len >> (i * 8)) & 0xFF;
        }

        /* insert seq */
        len = len - (index - *ofs);
        buf[index++] = seq;

        if (!hdr_len) {
                buf[index++] = len;
        } else {
                buf[index++] = 0x80 | hdr_len;
                for (i = hdr_len - 1; i >= 0; i--)
                        buf[index++] = (len >> (i * 8)) & 0xFF;
        }

        *ofs += (index - *ofs);
}

static int compute_asn_hdr_len_bytes(int len)
{
        if (len > 0xFFFFFF)
                return 4;
        else if (len > 0xFFFF)
                return 3;
        else if (len > 0xFF)
                return 2;
        else if (len > 0x7F)
                return 1;
        else
                return 0;
}

int build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer, u16 *buflen,
                                  char *ntlm_blob, int ntlm_blob_len)
{
        char *buf;
        unsigned int ofs = 0;
        int neg_result_len = 4 + compute_asn_hdr_len_bytes(1) * 2 + 1;
        int oid_len = 4 + compute_asn_hdr_len_bytes(NTLMSSP_OID_LEN) * 2 +
                NTLMSSP_OID_LEN;
        int ntlmssp_len = 4 + compute_asn_hdr_len_bytes(ntlm_blob_len) * 2 +
                ntlm_blob_len;
        int total_len = 4 + compute_asn_hdr_len_bytes(neg_result_len +
                        oid_len + ntlmssp_len) * 2 +
                        neg_result_len + oid_len + ntlmssp_len;

        buf = kmalloc(total_len, KSMBD_DEFAULT_GFP);
        if (!buf)
                return -ENOMEM;

        /* insert main gss header */
        encode_asn_tag(buf, &ofs, 0xa1, 0x30, neg_result_len + oid_len +
                        ntlmssp_len);

        /* insert neg result */
        encode_asn_tag(buf, &ofs, 0xa0, 0x0a, 1);
        buf[ofs++] = 1;

        /* insert oid */
        encode_asn_tag(buf, &ofs, 0xa1, 0x06, NTLMSSP_OID_LEN);
        memcpy(buf + ofs, NTLMSSP_OID_STR, NTLMSSP_OID_LEN);
        ofs += NTLMSSP_OID_LEN;

        /* insert response token - ntlmssp blob */
        encode_asn_tag(buf, &ofs, 0xa2, 0x04, ntlm_blob_len);
        memcpy(buf + ofs, ntlm_blob, ntlm_blob_len);
        ofs += ntlm_blob_len;

        *pbuffer = buf;
        *buflen = total_len;
        return 0;
}


int build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer, u16 *buflen,
                                   int neg_result)
{
        char *buf;
        unsigned int ofs = 0;
        int neg_result_len = 4 + compute_asn_hdr_len_bytes(1) * 2 + 1;
        int total_len = 4 + compute_asn_hdr_len_bytes(neg_result_len) * 2 +
                neg_result_len;

        buf = kmalloc(total_len, KSMBD_DEFAULT_GFP);
        if (!buf)
                return -ENOMEM;

        /* insert main gss header */
        encode_asn_tag(buf, &ofs, 0xa1, 0x30, neg_result_len);

        /* insert neg result */
        encode_asn_tag(buf, &ofs, 0xa0, 0x0a, 1);
        if (neg_result)
                buf[ofs++] = 2;
        else
                buf[ofs++] = 0;

        *pbuffer = buf;
        *buflen = total_len;
        return 0;
}


</document_content>
</document>
<document index="2">
<source>./kernel/fs/smb/server/auth.c</source>
<document_content>
/**
 * ksmbd_build_ntlmssp_challenge_blob() - helper function to construct
 * challenge blob
 * @chgblob: challenge blob source pointer to initialize
 * @conn:       connection
 *
 */
unsigned int
ksmbd_build_ntlmssp_challenge_blob(struct challenge_message *chgblob,
                                   struct ksmbd_conn *conn)
{
        struct target_info *tinfo;
        wchar_t *name;
        __u8 *target_name;
        unsigned int flags, blob_off, blob_len, type, target_info_len = 0;
        int len, uni_len, conv_len;
        int cflags = conn->ntlmssp.client_flags;

        memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);
        chgblob->MessageType = NtLmChallenge;

        flags = NTLMSSP_NEGOTIATE_UNICODE |
                NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |
                NTLMSSP_NEGOTIATE_TARGET_INFO;

        if (cflags & NTLMSSP_NEGOTIATE_SIGN) {
                flags |= NTLMSSP_NEGOTIATE_SIGN;
                flags |= cflags & (NTLMSSP_NEGOTIATE_128 |
                                   NTLMSSP_NEGOTIATE_56);
        }

        if (cflags & NTLMSSP_NEGOTIATE_SEAL && smb3_encryption_negotiated(conn))
                flags |= NTLMSSP_NEGOTIATE_SEAL;

        if (cflags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
                flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;

        if (cflags & NTLMSSP_REQUEST_TARGET)
                flags |= NTLMSSP_REQUEST_TARGET;

        if (conn->use_spnego &&
            (cflags & NTLMSSP_NEGOTIATE_EXTENDED_SEC))
                flags |= NTLMSSP_NEGOTIATE_EXTENDED_SEC;

        if (cflags & NTLMSSP_NEGOTIATE_KEY_XCH)
                flags |= NTLMSSP_NEGOTIATE_KEY_XCH;

        chgblob->NegotiateFlags = cpu_to_le32(flags);
        len = strlen(ksmbd_netbios_name());
        name = kmalloc(2 + UNICODE_LEN(len), KSMBD_DEFAULT_GFP);
        if (!name)
                return -ENOMEM;

        conv_len = smb_strtoUTF16((__le16 *)name, ksmbd_netbios_name(), len,
                                  conn->local_nls);
        if (conv_len < 0 || conv_len > len) {
                kfree(name);
                return -EINVAL;
        }

        uni_len = UNICODE_LEN(conv_len);

        blob_off = sizeof(struct challenge_message);
        blob_len = blob_off + uni_len;

        chgblob->TargetName.Length = cpu_to_le16(uni_len);
        chgblob->TargetName.MaximumLength = cpu_to_le16(uni_len);
        chgblob->TargetName.BufferOffset = cpu_to_le32(blob_off);

        /* Initialize random conn challenge */
        get_random_bytes(conn->ntlmssp.cryptkey, sizeof(__u64));
        memcpy(chgblob->Challenge, conn->ntlmssp.cryptkey,
               CIFS_CRYPTO_KEY_SIZE);

        /* Add Target Information to security buffer */
        chgblob->TargetInfoArray.BufferOffset = cpu_to_le32(blob_len);

        target_name = (__u8 *)chgblob + blob_off;
        memcpy(target_name, name, uni_len);
        tinfo = (struct target_info *)(target_name + uni_len);

        chgblob->TargetInfoArray.Length = 0;
        /* Add target info list for NetBIOS/DNS settings */
        for (type = NTLMSSP_AV_NB_COMPUTER_NAME;
             type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {
                tinfo->Type = cpu_to_le16(type);
                tinfo->Length = cpu_to_le16(uni_len);
                memcpy(tinfo->Content, name, uni_len);
                tinfo = (struct target_info *)((char *)tinfo + 4 + uni_len);
                target_info_len += 4 + uni_len;
        }

        /* Add terminator subblock */
        tinfo->Type = 0;
        tinfo->Length = 0;
        target_info_len += 4;

        chgblob->TargetInfoArray.Length = cpu_to_le16(target_info_len);
        chgblob->TargetInfoArray.MaximumLength = cpu_to_le16(target_info_len);
        blob_len += target_info_len;
        kfree(name);
        ksmbd_debug(AUTH, "NTLMSSP SecurityBufferLength %d\n", blob_len);
        return blob_len;
}

/**
 * ksmbd_decode_ntlmssp_neg_blob() - helper function to construct
 * negotiate blob
 * @negblob: negotiate blob source pointer
 * @blob_len:   length of the @authblob message
 * @conn:       connection
 *
 */
int ksmbd_decode_ntlmssp_neg_blob(struct negotiate_message *negblob,
                                  int blob_len, struct ksmbd_conn *conn)
{
        if (blob_len < sizeof(struct negotiate_message)) {
                ksmbd_debug(AUTH, "negotiate blob len %d too small\n",
                            blob_len);
                return -EINVAL;
        }

        if (memcmp(negblob->Signature, "NTLMSSP", 8)) {
                ksmbd_debug(AUTH, "blob signature incorrect %s\n",
                            negblob->Signature);
                return -EINVAL;
        }

        conn->ntlmssp.client_flags = le32_to_cpu(negblob->NegotiateFlags);
        return 0;
}

/**
 * ksmbd_build_ntlmssp_challenge_blob() - helper function to construct
 * challenge blob
 * @chgblob: challenge blob source pointer to initialize
 * @conn:       connection
 *
 */
unsigned int
ksmbd_build_ntlmssp_challenge_blob(struct challenge_message *chgblob,
                                   struct ksmbd_conn *conn)
{
        struct target_info *tinfo;
        wchar_t *name;
        __u8 *target_name;
        unsigned int flags, blob_off, blob_len, type, target_info_len = 0;
        int len, uni_len, conv_len;
        int cflags = conn->ntlmssp.client_flags;

        memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);
        chgblob->MessageType = NtLmChallenge;

        flags = NTLMSSP_NEGOTIATE_UNICODE |
                NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |
                NTLMSSP_NEGOTIATE_TARGET_INFO;

        if (cflags & NTLMSSP_NEGOTIATE_SIGN) {
                flags |= NTLMSSP_NEGOTIATE_SIGN;
                flags |= cflags & (NTLMSSP_NEGOTIATE_128 |
                                   NTLMSSP_NEGOTIATE_56);
        }

        if (cflags & NTLMSSP_NEGOTIATE_SEAL && smb3_encryption_negotiated(conn))
                flags |= NTLMSSP_NEGOTIATE_SEAL;

        if (cflags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
                flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;

        if (cflags & NTLMSSP_REQUEST_TARGET)
                flags |= NTLMSSP_REQUEST_TARGET;

        if (conn->use_spnego &&
            (cflags & NTLMSSP_NEGOTIATE_EXTENDED_SEC))
                flags |= NTLMSSP_NEGOTIATE_EXTENDED_SEC;

        if (cflags & NTLMSSP_NEGOTIATE_KEY_XCH)
                flags |= NTLMSSP_NEGOTIATE_KEY_XCH;

        chgblob->NegotiateFlags = cpu_to_le32(flags);
        len = strlen(ksmbd_netbios_name());
        name = kmalloc(2 + UNICODE_LEN(len), KSMBD_DEFAULT_GFP);
        if (!name)
                return -ENOMEM;

        conv_len = smb_strtoUTF16((__le16 *)name, ksmbd_netbios_name(), len,
                                  conn->local_nls);
        if (conv_len < 0 || conv_len > len) {
                kfree(name);
                return -EINVAL;
        }

        uni_len = UNICODE_LEN(conv_len);

        blob_off = sizeof(struct challenge_message);
        blob_len = blob_off + uni_len;

        chgblob->TargetName.Length = cpu_to_le16(uni_len);
        chgblob->TargetName.MaximumLength = cpu_to_le16(uni_len);
        chgblob->TargetName.BufferOffset = cpu_to_le32(blob_off);

        /* Initialize random conn challenge */
        get_random_bytes(conn->ntlmssp.cryptkey, sizeof(__u64));
        memcpy(chgblob->Challenge, conn->ntlmssp.cryptkey,
               CIFS_CRYPTO_KEY_SIZE);

        /* Add Target Information to security buffer */
        chgblob->TargetInfoArray.BufferOffset = cpu_to_le32(blob_len);

        target_name = (__u8 *)chgblob + blob_off;
        memcpy(target_name, name, uni_len);
        tinfo = (struct target_info *)(target_name + uni_len);

        chgblob->TargetInfoArray.Length = 0;
        /* Add target info list for NetBIOS/DNS settings */
        for (type = NTLMSSP_AV_NB_COMPUTER_NAME;
             type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {
                tinfo->Type = cpu_to_le16(type);
                tinfo->Length = cpu_to_le16(uni_len);
                memcpy(tinfo->Content, name, uni_len);
                tinfo = (struct target_info *)((char *)tinfo + 4 + uni_len);
                target_info_len += 4 + uni_len;
        }

        /* Add terminator subblock */
        tinfo->Type = 0;
        tinfo->Length = 0;
        target_info_len += 4;

        chgblob->TargetInfoArray.Length = cpu_to_le16(target_info_len);
        chgblob->TargetInfoArray.MaximumLength = cpu_to_le16(target_info_len);
        blob_len += target_info_len;
        kfree(name);
        ksmbd_debug(AUTH, "NTLMSSP SecurityBufferLength %d\n", blob_len);
        return blob_len;
}

int ksmbd_gen_preauth_integrity_hash(struct ksmbd_conn *conn, char *buf,
                                     __u8 *pi_hash)
{
        int rc;
        struct smb2_hdr *rcv_hdr = smb2_get_msg(buf);
        char *all_bytes_msg = (char *)&rcv_hdr->ProtocolId;
        int msg_size = get_rfc1002_len(buf);
        struct ksmbd_crypto_ctx *ctx = NULL;

        if (conn->preauth_info->Preauth_HashId !=
            SMB2_PREAUTH_INTEGRITY_SHA512)
                return -EINVAL;

        ctx = ksmbd_crypto_ctx_find_sha512();
        if (!ctx) {
                ksmbd_debug(AUTH, "could not alloc sha512\n");
                return -ENOMEM;
        }

        rc = crypto_shash_init(CRYPTO_SHA512(ctx));
        if (rc) {
                ksmbd_debug(AUTH, "could not init shashn");
                goto out;
        }

        rc = crypto_shash_update(CRYPTO_SHA512(ctx), pi_hash, 64);
        if (rc) {
                ksmbd_debug(AUTH, "could not update with n\n");
                goto out;
        }

        rc = crypto_shash_update(CRYPTO_SHA512(ctx), all_bytes_msg, msg_size);
        if (rc) {
                ksmbd_debug(AUTH, "could not update with n\n");
                goto out;
        }

        rc = crypto_shash_final(CRYPTO_SHA512(ctx), pi_hash);
        if (rc) {
                ksmbd_debug(AUTH, "Could not generate hash err : %d\n", rc);
                goto out;
        }
out:
        ksmbd_release_crypto_ctx(ctx);
        return rc;
}

int ksmbd_krb5_authenticate(struct ksmbd_session *sess, char *in_blob,
			    int in_len, char *out_blob, int *out_len)
{
	struct ksmbd_spnego_authen_response *resp;
	struct ksmbd_login_response_ext *resp_ext = NULL;
	struct ksmbd_user *user = NULL;
	int retval;

	resp = ksmbd_ipc_spnego_authen_request(in_blob, in_len);
	if (!resp) {
		ksmbd_debug(AUTH, "SPNEGO_AUTHEN_REQUEST failure\n");
		return -EINVAL;
	}

	if (!(resp->login_response.status & KSMBD_USER_FLAG_OK)) {
		ksmbd_debug(AUTH, "krb5 authentication failure\n");
		retval = -EPERM;
		goto out;
	}

	if (*out_len <= resp->spnego_blob_len) {
		ksmbd_debug(AUTH, "buf len %d, but blob len %d\n",
			    *out_len, resp->spnego_blob_len);
		retval = -EINVAL;
		goto out;
	}

	if (resp->session_key_len > sizeof(sess->sess_key)) {
		ksmbd_debug(AUTH, "session key is too long\n");
		retval = -EINVAL;
		goto out;
	}

	if (resp->login_response.status & KSMBD_USER_FLAG_EXTENSION)
		resp_ext = ksmbd_ipc_login_request_ext(resp->login_response.account);

	user = ksmbd_alloc_user(&resp->login_response, resp_ext);
	if (!user) {
		ksmbd_debug(AUTH, "login failure\n");
		retval = -ENOMEM;
		goto out;
	}
	sess->user = user;

	memcpy(sess->sess_key, resp->payload, resp->session_key_len);
	memcpy(out_blob, resp->payload + resp->session_key_len,
	       resp->spnego_blob_len);
	*out_len = resp->spnego_blob_len;
	retval = 0;
out:
	kvfree(resp);
	return retval;
}

int ksmbd_gen_smb311_encryptionkey(struct ksmbd_conn *conn,
                                   struct ksmbd_session *sess)
{
        struct derivation_twin twin;
        struct derivation *d;

        d = &twin.encryption;
        d->label.iov_base = "SMBS2CCipherKey";
        d->label.iov_len = 16;
        d->context.iov_base = sess->Preauth_HashValue;
        d->context.iov_len = 64;

        d = &twin.decryption;
        d->label.iov_base = "SMBC2SCipherKey";
        d->label.iov_len = 16;
        d->context.iov_base = sess->Preauth_HashValue;
        d->context.iov_len = 64;

        return generate_smb3encryptionkey(conn, sess, &twin);
}

static int generate_smb3encryptionkey(struct ksmbd_conn *conn,
                                      struct ksmbd_session *sess,
                                      const struct derivation_twin *ptwin)
{
        int rc;

        rc = generate_key(conn, sess, ptwin->encryption.label,
                          ptwin->encryption.context, sess->smb3encryptionkey,
                          SMB3_ENC_DEC_KEY_SIZE);
        if (rc)
                return rc;

        rc = generate_key(conn, sess, ptwin->decryption.label,
                          ptwin->decryption.context,
                          sess->smb3decryptionkey, SMB3_ENC_DEC_KEY_SIZE);
        if (rc)
                return rc;

        ksmbd_debug(AUTH, "dumping generated AES encryption keys\n");
        ksmbd_debug(AUTH, "Cipher type   %d\n", conn->cipher_type);
        ksmbd_debug(AUTH, "Session Id    %llu\n", sess->id);
        ksmbd_debug(AUTH, "Session Key   %*ph\n",
                    SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
        if (conn->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||
            conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM) {
                ksmbd_debug(AUTH, "ServerIn Key  %*ph\n",
                            SMB3_GCM256_CRYPTKEY_SIZE, sess->smb3encryptionkey);
                ksmbd_debug(AUTH, "ServerOut Key %*ph\n",
                            SMB3_GCM256_CRYPTKEY_SIZE, sess->smb3decryptionkey);
        } else {
                ksmbd_debug(AUTH, "ServerIn Key  %*ph\n",
                            SMB3_GCM128_CRYPTKEY_SIZE, sess->smb3encryptionkey);
                ksmbd_debug(AUTH, "ServerOut Key %*ph\n",
                            SMB3_GCM128_CRYPTKEY_SIZE, sess->smb3decryptionkey);
        }
        return 0;
}

static int generate_smb3signingkey(struct ksmbd_session *sess,
                                   struct ksmbd_conn *conn,
                                   const struct derivation *signing)
{
        int rc;
        struct channel *chann;
        char *key;

        chann = lookup_chann_list(sess, conn);
        if (!chann)
                return 0;

        if (conn->dialect >= SMB30_PROT_ID && signing->binding)
                key = chann->smb3signingkey;
        else
                key = sess->smb3signingkey;

        rc = generate_key(conn, sess, signing->label, signing->context, key,
                          SMB3_SIGN_KEY_SIZE);
        if (rc)
                return rc;

        if (!(conn->dialect >= SMB30_PROT_ID && signing->binding))
                memcpy(chann->smb3signingkey, key, SMB3_SIGN_KEY_SIZE);

        ksmbd_debug(AUTH, "dumping generated AES signing keys\n");
        ksmbd_debug(AUTH, "Session Id    %llu\n", sess->id);
        ksmbd_debug(AUTH, "Session Key   %*ph\n",
                    SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
        ksmbd_debug(AUTH, "Signing Key   %*ph\n",
                    SMB3_SIGN_KEY_SIZE, key);
        return 0;
}

int ksmbd_gen_smb311_signingkey(struct ksmbd_session *sess,
                                struct ksmbd_conn *conn)
{
        struct derivation d;

        d.label.iov_base = "SMBSigningKey";
        d.label.iov_len = 14;
        if (conn->binding) {
                struct preauth_session *preauth_sess;

                preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
                if (!preauth_sess)
                        return -ENOENT;
                d.context.iov_base = preauth_sess->Preauth_HashValue;
        } else {
                d.context.iov_base = sess->Preauth_HashValue;
        }
        d.context.iov_len = 64;
        d.binding = conn->binding;

        return generate_smb3signingkey(sess, conn, &d);
}

</document_content>
</document>
<document index="3">
<source>./kernel/fs/smb/server/connection.c</source>
<document_content>
bool ksmbd_conn_alive(struct ksmbd_conn *conn)
{
	if (!ksmbd_server_running())
		return false;

	if (ksmbd_conn_exiting(conn))
		return false;

	if (kthread_should_stop())
		return false;

	if (atomic_read(&conn->stats.open_files_count) > 0)
		return true;

	/*
	 * Stop current session if the time that get last request from client
	 * is bigger than deadtime user configured and opening file count is
	 * zero.
	 */
	if (server_conf.deadtime > 0 &&
	    time_after(jiffies, conn->last_active + server_conf.deadtime)) {
		ksmbd_debug(CONN, "No response from client in %lu minutes\n",
			    server_conf.deadtime / SMB_ECHO_INTERVAL);
		return false;
	}
	return true;
}


/**
 * ksmbd_conn_handler_loop() - session thread to listen on new smb requests
 * @p:		connection instance
 *
 * One thread each per connection
 *
 * Return:	0 on success
 */
int ksmbd_conn_handler_loop(void *p)
{
	struct ksmbd_conn *conn = (struct ksmbd_conn *)p;
	struct ksmbd_transport *t = conn->transport;
	unsigned int pdu_size, max_allowed_pdu_size, max_req;
	char hdr_buf[4] = {0,};
	int size;

	mutex_init(&conn->srv_mutex);
	__module_get(THIS_MODULE);

	if (t->ops->prepare && t->ops->prepare(t))
		goto out;

	max_req = server_conf.max_inflight_req;
	conn->last_active = jiffies;
	set_freezable();
	while (ksmbd_conn_alive(conn)) {
		if (try_to_freeze())
			continue;

		kvfree(conn->request_buf);
		conn->request_buf = NULL;

recheck:
		if (atomic_read(&conn->req_running) + 1 > max_req) {
			wait_event_interruptible(conn->req_running_q,
				atomic_read(&conn->req_running) < max_req);
			goto recheck;
		}

		size = t->ops->read(t, hdr_buf, sizeof(hdr_buf), -1);
		if (size != sizeof(hdr_buf))
			break;

		pdu_size = get_rfc1002_len(hdr_buf);
		ksmbd_debug(CONN, "RFC1002 header %u bytes\n", pdu_size);

		if (ksmbd_conn_good(conn))
			max_allowed_pdu_size =
				SMB3_MAX_MSGSIZE + conn->vals->max_write_size;
		else
			max_allowed_pdu_size = SMB3_MAX_MSGSIZE;

		if (pdu_size > max_allowed_pdu_size) {
			pr_err_ratelimited("PDU length(%u) exceeded maximum allowed pdu size(%u) on connection(%d)\n",
					pdu_size, max_allowed_pdu_size,
					READ_ONCE(conn->status));
			break;
		}

		/*
		 * Check maximum pdu size(0x00FFFFFF).
		 */
		if (pdu_size > MAX_STREAM_PROT_LEN)
			break;

		if (pdu_size < SMB1_MIN_SUPPORTED_HEADER_SIZE)
			break;

		/* 4 for rfc1002 length field */
		/* 1 for implied bcc[0] */
		size = pdu_size + 4 + 1;
		conn->request_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);
		if (!conn->request_buf)
			break;

		memcpy(conn->request_buf, hdr_buf, sizeof(hdr_buf));

		/*
		 * We already read 4 bytes to find out PDU size, now
		 * read in PDU
		 */
		size = t->ops->read(t, conn->request_buf + 4, pdu_size, 2);
		if (size < 0) {
			pr_err("sock_read failed: %d\n", size);
			break;
		}

		if (size != pdu_size) {
			pr_err("PDU error. Read: %d, Expected: %d\n",
			       size, pdu_size);
			continue;
		}

		if (!ksmbd_smb_request(conn))
			break;

		if (((struct smb2_hdr *)smb2_get_msg(conn->request_buf))->ProtocolId ==
		    SMB2_PROTO_NUMBER) {
			if (pdu_size < SMB2_MIN_SUPPORTED_HEADER_SIZE)
				break;
		}

		if (!default_conn_ops.process_fn) {
			pr_err("No connection request callback\n");
			break;
		}

		if (default_conn_ops.process_fn(conn)) {
			pr_err("Cannot handle request\n");
			break;
		}
	}

out:
	ksmbd_conn_set_releasing(conn);
	/* Wait till all reference dropped to the Server object*/
	ksmbd_debug(CONN, "Wait for all pending requests(%d)\n", atomic_read(&conn->r_count));
	wait_event(conn->r_count_q, atomic_read(&conn->r_count) == 0);

	if (IS_ENABLED(CONFIG_UNICODE))
		utf8_unload(conn->um);
	unload_nls(conn->local_nls);
	if (default_conn_ops.terminate_fn)
		default_conn_ops.terminate_fn(conn);
	t->ops->disconnect(t);
	module_put(THIS_MODULE);
	return 0;
}

void ksmbd_conn_lock(struct ksmbd_conn *conn)
{
        mutex_lock(&conn->srv_mutex);
}

void ksmbd_conn_unlock(struct ksmbd_conn *conn)
{
        mutex_unlock(&conn->srv_mutex);
}

void ksmbd_all_conn_set_status(u64 sess_id, u32 status)
{
        struct ksmbd_conn *conn;

        down_read(&conn_list_lock);
        list_for_each_entry(conn, &conn_list, conns_list) {
                if (conn->binding || xa_load(&conn->sessions, sess_id))
                        WRITE_ONCE(conn->status, status);
        }
        up_read(&conn_list_lock);
}

int ksmbd_conn_wait_idle_sess_id(struct ksmbd_conn *curr_conn, u64 sess_id)
{
        struct ksmbd_conn *conn;
        int rc, retry_count = 0, max_timeout = 120;
        int rcount = 1;

retry_idle:
        if (retry_count >= max_timeout)
                return -EIO;

        down_read(&conn_list_lock);
        list_for_each_entry(conn, &conn_list, conns_list) {
                if (conn->binding || xa_load(&conn->sessions, sess_id)) {
                        if (conn == curr_conn)
                                rcount = 2;
                        if (atomic_read(&conn->req_running) >= rcount) {
                                rc = wait_event_timeout(conn->req_running_q,
                                        atomic_read(&conn->req_running) < rcount,
                                        HZ);
                                if (!rc) {
                                        up_read(&conn_list_lock);
                                        retry_count++;
                                        goto retry_idle;
                                }
                        }
                }
        }
        up_read(&conn_list_lock);

        return 0;
}

bool ksmbd_conn_lookup_dialect(struct ksmbd_conn *c)
{
        struct ksmbd_conn *t;
        bool ret = false;

        down_read(&conn_list_lock);
        list_for_each_entry(t, &conn_list, conns_list) {
                if (memcmp(t->ClientGUID, c->ClientGUID, SMB2_CLIENT_GUID_SIZE))
                        continue;

                ret = true;
                break;
        }
        up_read(&conn_list_lock);
        return ret;
}

</document_content>
</document>
<document index="4">
<source>./kernel/fs/smb/server/connection.h</source>
<document_content>

struct ksmbd_conn {
	struct smb_version_values	*vals;
	struct smb_version_ops		*ops;
	struct smb_version_cmds		*cmds;
	unsigned int			max_cmds;
	struct mutex			srv_mutex;
	int				status;
	unsigned int			cli_cap;
	char				*request_buf;
	struct ksmbd_transport		*transport;
	struct nls_table		*local_nls;
	struct unicode_map		*um;
	struct list_head		conns_list;
	struct rw_semaphore		session_lock;
	/* smb session 1 per user */
	struct xarray			sessions;
	unsigned long			last_active;
	/* How many request are running currently */
	atomic_t			req_running;
	/* References which are made for this Server object*/
	atomic_t			r_count;
	unsigned int			total_credits;
	unsigned int			outstanding_credits;
	spinlock_t			credits_lock;
	wait_queue_head_t		req_running_q;
	wait_queue_head_t		r_count_q;
	/* Lock to protect requests list*/
	spinlock_t			request_lock;
	struct list_head		requests;
	struct list_head		async_requests;
	int				connection_type;
	struct ksmbd_stats		stats;
	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];
	struct ntlmssp_auth		ntlmssp;

	spinlock_t			llist_lock;
	struct list_head		lock_list;

	struct preauth_integrity_info	*preauth_info;

	bool				need_neg;
	unsigned int			auth_mechs;
	unsigned int			preferred_auth_mech;
	bool				sign;
	bool				use_spnego:1;
	__u16				cli_sec_mode;
	__u16				srv_sec_mode;
	/* dialect index that server chose */
	__u16				dialect;

	char				*mechToken;
	unsigned int			mechTokenLen;

	struct ksmbd_conn_ops	*conn_ops;

	/* Preauth Session Table */
	struct list_head		preauth_sess_table;

	struct sockaddr_storage		peer_addr;

	/* Identifier for async message */
	struct ida			async_ida;

	__le16				cipher_type;
	__le16				compress_algorithm;
	bool				posix_ext_supported;
	bool				signing_negotiated;
	__le16				signing_algorithm;
	bool				binding;
	atomic_t			refcnt;
};

static inline bool ksmbd_conn_good(struct ksmbd_conn *conn)
{
	return READ_ONCE(conn->status) == KSMBD_SESS_GOOD;
}

static inline bool ksmbd_conn_need_reconnect(struct ksmbd_conn *conn)
{
	return READ_ONCE(conn->status) == KSMBD_SESS_NEED_RECONNECT;
}

static inline bool ksmbd_conn_exiting(struct ksmbd_conn *conn)
{
	return READ_ONCE(conn->status) == KSMBD_SESS_EXITING;
}

static inline bool ksmbd_conn_need_setup(struct ksmbd_conn *conn)
{
        return READ_ONCE(conn->status) == KSMBD_SESS_NEED_SETUP;
}

</document_content>
</document>
<document index="5">
<source>./kernel/fs/smb/server/crypto_ctx.c</source>
<document_content>
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void)
{
        return ____crypto_shash_ctx_find(CRYPTO_SHASH_SHA512);
}

void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx)
{
        if (!ctx)
                return;

        spin_lock(&ctx_list.ctx_lock);
        if (ctx_list.avail_ctx <= num_online_cpus()) {
                list_add(&ctx->list, &ctx_list.idle_ctx);
                spin_unlock(&ctx_list.ctx_lock);
                wake_up(&ctx_list.ctx_wait);
                return;
        }

        ctx_list.avail_ctx--;
        spin_unlock(&ctx_list.ctx_lock);
        ctx_free(ctx);
}

</document_content>
</document>
<document index="6">
<source>./kernel/fs/smb/server/ksmbd_netlink.h</source>
<document_content>
/*
 * IPC user login request.
 */
struct ksmbd_login_request {
        __u32   handle;
        __s8    account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ]; /* user account name */
        __u32   reserved[16];                           /* Reserved room */
};

/*
 * IPC user login response.
 */
struct ksmbd_login_response {
        __u32   handle;
        __u32   gid;                                    /* group id */
        __u32   uid;                                    /* user id */
        __s8    account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ]; /* user account name */
        __u16   status;
        __u16   hash_sz;                        /* hash size */
        __s8    hash[KSMBD_REQ_MAX_HASH_SZ];    /* password hash */
        __u32   reserved[16];                   /* Reserved room */
};

/*
 * IPC user login response extension.
 */
struct ksmbd_login_response_ext {
        __u32   handle;
        __s32   ngroups;                        /* supplementary group count */
        __s8    reserved[128];                  /* Reserved room */
        __s8    ____payload[];
};

</document_content>
</document>
<document index="7">
<source>./kernel/fs/smb/server/ksmbd_work.c</source>
<document_content>
static inline void __ksmbd_iov_pin(struct ksmbd_work *work, void *ib,
                                   unsigned int ib_len)
{
        work->iov[++work->iov_idx].iov_base = ib;
        work->iov[work->iov_idx].iov_len = ib_len;
        work->iov_cnt++;
}

static int __ksmbd_iov_pin_rsp(struct ksmbd_work *work, void *ib, int len,
                               void *aux_buf, unsigned int aux_size)
{
        struct aux_read *ar = NULL;
        int need_iov_cnt = 1;

        if (aux_size) {
                need_iov_cnt++;
                ar = kmalloc(sizeof(struct aux_read), KSMBD_DEFAULT_GFP);
                if (!ar)
                        return -ENOMEM;
        }

        if (work->iov_alloc_cnt < work->iov_cnt + need_iov_cnt) {
                struct kvec *new;

                work->iov_alloc_cnt += 4;
                new = krealloc(work->iov,
                               sizeof(struct kvec) * work->iov_alloc_cnt,
                               KSMBD_DEFAULT_GFP | __GFP_ZERO);
                if (!new) {
                        kfree(ar);
                        work->iov_alloc_cnt -= 4;
                        return -ENOMEM;
                }
                work->iov = new;
        }

        /* Plus rfc_length size on first iov */
        if (!work->iov_idx) {
                work->iov[work->iov_idx].iov_base = work->response_buf;
                *(__be32 *)work->iov[0].iov_base = 0;
                work->iov[work->iov_idx].iov_len = 4;
                work->iov_cnt++;
        }

        __ksmbd_iov_pin(work, ib, len);
        inc_rfc1001_len(work->iov[0].iov_base, len);

        if (aux_size) {
                __ksmbd_iov_pin(work, aux_buf, aux_size);
                inc_rfc1001_len(work->iov[0].iov_base, aux_size);

                ar->buf = aux_buf;
                list_add(&ar->entry, &work->aux_read_list);
        }

        return 0;
}

int ksmbd_iov_pin_rsp(struct ksmbd_work *work, void *ib, int len)
{
        return __ksmbd_iov_pin_rsp(work, ib, len, NULL, 0);
}

</document_content>
</document>
<document index="8">
<source>./kernel/fs/smb/server/ksmbd_work.h</source>
<document_content>
/* one of these for every pending CIFS request at the connection */
struct ksmbd_work {
	/* Server corresponding to this mid */
	struct ksmbd_conn               *conn;
	struct ksmbd_session            *sess;
	struct ksmbd_tree_connect       *tcon;

	/* Pointer to received SMB header */
	void                            *request_buf;
	/* Response buffer */
	void                            *response_buf;

	struct list_head		aux_read_list;

	struct kvec			*iov;
	int				iov_alloc_cnt;
	int				iov_cnt;
	int				iov_idx;

	/* Next cmd hdr in compound req buf*/
	int                             next_smb2_rcv_hdr_off;
	/* Next cmd hdr in compound rsp buf*/
	int                             next_smb2_rsp_hdr_off;
	/* Current cmd hdr in compound rsp buf*/
	int                             curr_smb2_rsp_hdr_off;

	/*
	 * Current Local FID assigned compound response if SMB2 CREATE
	 * command is present in compound request
	 */
	u64				compound_fid;
	u64				compound_pfid;
	u64				compound_sid;

	const struct cred		*saved_cred;

	/* Number of granted credits */
	unsigned int			credits_granted;

	/* response smb header size */
	unsigned int                    response_sz;

	void				*tr_buf;

	unsigned char			state;
	/* No response for cancelled request */
	bool                            send_no_response:1;
	/* Request is encrypted */
	bool                            encrypted:1;
	/* Is this SYNC or ASYNC ksmbd_work */
	bool                            asynchronous:1;
	bool                            need_invalidate_rkey:1;

	unsigned int                    remote_key;
	/* cancel works */
	int                             async_id;
	void                            **cancel_argv;
	void                            (*cancel_fn)(void **argv);

	struct work_struct              work;
	/* List head at conn->requests */
	struct list_head                request_entry;
	/* List head at conn->async_requests */
	struct list_head                async_request_entry;
	struct list_head                fp_entry;
};

/**
 * ksmbd_req_buf_next - Get next buffer on compound request.
 * @work: smb work containing response buffer
 */
static inline void *ksmbd_req_buf_next(struct ksmbd_work *work)
{
	return work->request_buf + work->next_smb2_rcv_hdr_off + 4;
}

/**
 * ksmbd_resp_buf_next - Get next buffer on compound response.
 * @work: smb work containing response buffer
 */
static inline void *ksmbd_resp_buf_next(struct ksmbd_work *work)
{
        return work->response_buf + work->next_smb2_rsp_hdr_off + 4;
}


</document_content>
</document>
<document index="9">
<source>./kernel/fs/smb/server/ntlmssp.h</source>
<document_content>
struct negotiate_message {
        __u8 Signature[sizeof(NTLMSSP_SIGNATURE)];
        __le32 MessageType;     /* NtLmNegotiate = 1 */
        __le32 NegotiateFlags;
        struct security_buffer DomainName;      /* RFC 1001 style and ASCII */
        struct security_buffer WorkstationName; /* RFC 1001 and ASCII */
        /*
         * struct security_buffer for version info not present since we
         * do not set the version is present flag
         */
        char DomainString[];
        /* followed by WorkstationString */
} __packed;

struct challenge_message {
        __u8 Signature[sizeof(NTLMSSP_SIGNATURE)];
        __le32 MessageType;   /* NtLmChallenge = 2 */
        struct security_buffer TargetName;
        __le32 NegotiateFlags;
        __u8 Challenge[CIFS_CRYPTO_KEY_SIZE];
        __u8 Reserved[8];
        struct security_buffer TargetInfoArray;
        /*
         * struct security_buffer for version info not present since we
         * do not set the version is present flag
         */
} __packed;

struct authenticate_message {
        __u8 Signature[sizeof(NTLMSSP_SIGNATURE)];
        __le32 MessageType;  /* NtLmsAuthenticate = 3 */
        struct security_buffer LmChallengeResponse;
        struct security_buffer NtChallengeResponse;
        struct security_buffer DomainName;
        struct security_buffer UserName;
        struct security_buffer WorkstationName;
        struct security_buffer SessionKey;
        __le32 NegotiateFlags;
        /*
         * struct security_buffer for version info not present since we
         * do not set the version is present flag
         */
        char UserString[];
} __packed;

struct ntlmv2_resp {
        char ntlmv2_hash[CIFS_ENCPWD_SIZE];
        __le32 blob_signature;
        __u32  reserved;
        __le64  time;
        __u64  client_chal; /* random */
        __u32  reserved2;
        /* array of name entries could follow ending in minimum 4 byte struct */
} __packed;

</document_content>
</document>
<document index="10">
<source>./kernel/fs/smb/server/server.c</source>
<document_content>
static int __process_request(struct ksmbd_work *work, struct ksmbd_conn *conn,
			     u16 *cmd)
{
	struct smb_version_cmds *cmds;
	u16 command;
	int ret;

	if (check_conn_state(work))
		return SERVER_HANDLER_CONTINUE;

	if (ksmbd_verify_smb_message(work)) {
		conn->ops->set_rsp_status(work, STATUS_INVALID_PARAMETER);
		return SERVER_HANDLER_ABORT;
	}

	command = conn->ops->get_cmd_val(work);
	*cmd = command;

andx_again:
	if (command >= conn->max_cmds) {
		conn->ops->set_rsp_status(work, STATUS_INVALID_PARAMETER);
		return SERVER_HANDLER_CONTINUE;
	}

	cmds = &conn->cmds[command];
	if (!cmds->proc) {
		ksmbd_debug(SMB, "*** not implemented yet cmd = %x\n", command);
		conn->ops->set_rsp_status(work, STATUS_NOT_IMPLEMENTED);
		return SERVER_HANDLER_CONTINUE;
	}

	if (work->sess && conn->ops->is_sign_req(work, command)) {
		ret = conn->ops->check_sign_req(work);
		if (!ret) {
			conn->ops->set_rsp_status(work, STATUS_ACCESS_DENIED);
			return SERVER_HANDLER_CONTINUE;
		}
	}

	ret = cmds->proc(work);

	if (ret < 0)
		ksmbd_debug(CONN, "Failed to process %u [%d]\n", command, ret);
	/* AndX commands - chained request can return positive values */
	else if (ret > 0) {
		command = ret;
		*cmd = command;
		goto andx_again;
	}

	if (work->send_no_response)
		return SERVER_HANDLER_ABORT;
	return SERVER_HANDLER_CONTINUE;
}

static void __handle_ksmbd_work(struct ksmbd_work *work,
				struct ksmbd_conn *conn)
{
	u16 command = 0;
	int rc;
	bool is_chained = false;

	if (conn->ops->is_transform_hdr &&
	    conn->ops->is_transform_hdr(work->request_buf)) {
		rc = conn->ops->decrypt_req(work);
		if (rc < 0)
			return;
		work->encrypted = true;
	}

	if (conn->ops->allocate_rsp_buf(work))
		return;

	rc = conn->ops->init_rsp_hdr(work);
	if (rc) {
		/* either uid or tid is not correct */
		conn->ops->set_rsp_status(work, STATUS_INVALID_HANDLE);
		goto send;
	}

	do {
		if (conn->ops->check_user_session) {
			rc = conn->ops->check_user_session(work);
			if (rc < 0) {
				if (rc == -EINVAL)
					conn->ops->set_rsp_status(work,
						STATUS_INVALID_PARAMETER);
				else
					conn->ops->set_rsp_status(work,
						STATUS_USER_SESSION_DELETED);
				goto send;
			} else if (rc > 0) {
				rc = conn->ops->get_ksmbd_tcon(work);
				if (rc < 0) {
					if (rc == -EINVAL)
						conn->ops->set_rsp_status(work,
							STATUS_INVALID_PARAMETER);
					else
						conn->ops->set_rsp_status(work,
							STATUS_NETWORK_NAME_DELETED);
					goto send;
				}
			}
		}

		rc = __process_request(work, conn, &command);
		if (rc == SERVER_HANDLER_ABORT)
			break;

		/*
		 * Call smb2_set_rsp_credits() function to set number of credits
		 * granted in hdr of smb2 response.
		 */
		if (conn->ops->set_rsp_credits) {
			spin_lock(&conn->credits_lock);
			rc = conn->ops->set_rsp_credits(work);
			spin_unlock(&conn->credits_lock);
			if (rc < 0) {
				conn->ops->set_rsp_status(work,
					STATUS_INVALID_PARAMETER);
				goto send;
			}
		}

		is_chained = is_chained_smb2_message(work);

		if (work->sess &&
		    (work->sess->sign || smb3_11_final_sess_setup_resp(work) ||
		     conn->ops->is_sign_req(work, command)))
			conn->ops->set_sign_rsp(work);
	} while (is_chained == true);

send:
	if (work->tcon)
		ksmbd_tree_connect_put(work->tcon);
	smb3_preauth_hash_rsp(work);
	if (work->sess && work->sess->enc && work->encrypted &&
	    conn->ops->encrypt_resp) {
		rc = conn->ops->encrypt_resp(work);
		if (rc < 0)
			conn->ops->set_rsp_status(work, STATUS_DATA_ERROR);
	}
	if (work->sess)
		ksmbd_user_session_put(work->sess);

	ksmbd_conn_write(work);
}


/**
 * handle_ksmbd_work() - process pending smb work requests
 * @wk:	smb work containing request command buffer
 *
 * called by kworker threads to processing remaining smb work requests
 */
static void handle_ksmbd_work(struct work_struct *wk)
{
	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);
	struct ksmbd_conn *conn = work->conn;

	atomic64_inc(&conn->stats.request_served);

	__handle_ksmbd_work(work, conn);

	ksmbd_conn_try_dequeue_request(work);
	ksmbd_free_work_struct(work);
	ksmbd_conn_r_count_dec(conn);
}

/**
 * queue_ksmbd_work() - queue a smb request to worker thread queue
 *		for processing smb command and sending response
 * @conn:	connection instance
 *
 * read remaining data from socket create and submit work.
 */
static int queue_ksmbd_work(struct ksmbd_conn *conn)
{
	struct ksmbd_work *work;
	int err;

	err = ksmbd_init_smb_server(conn);
	if (err)
		return 0;

	work = ksmbd_alloc_work_struct();
	if (!work) {
		pr_err("allocation for work failed\n");
		return -ENOMEM;
	}

	work->conn = conn;
	work->request_buf = conn->request_buf;
	conn->request_buf = NULL;

	ksmbd_conn_enqueue_request(work);
	ksmbd_conn_r_count_inc(conn);
	/* update activity on connection */
	conn->last_active = jiffies;
	INIT_WORK(&work->work, handle_ksmbd_work);
	ksmbd_queue_work(work);
	return 0;
}

static int ksmbd_server_process_request(struct ksmbd_conn *conn)
{
	return queue_ksmbd_work(conn);
}

static int ksmbd_server_terminate_conn(struct ksmbd_conn *conn)
{
	ksmbd_sessions_deregister(conn);
	destroy_lease_table(conn);
	return 0;
}

static void ksmbd_server_tcp_callbacks_init(void)
{
	struct ksmbd_conn_ops ops;

	ops.process_fn = ksmbd_server_process_request;
	ops.terminate_fn = ksmbd_server_terminate_conn;

	ksmbd_conn_init_server_callbacks(&ops);
}

</document_content>
</document>
<document index="11">
<source>./kernel/fs/smb/server/smb2ops.c</source>
<document_content>

static struct smb_version_ops smb3_11_server_ops = {
	.get_cmd_val		=	get_smb2_cmd_val,
	.init_rsp_hdr		=	init_smb2_rsp_hdr,
	.set_rsp_status		=	set_smb2_rsp_status,
	.allocate_rsp_buf       =       smb2_allocate_rsp_buf,
	.set_rsp_credits	=	smb2_set_rsp_credits,
	.check_user_session	=	smb2_check_user_session,
	.get_ksmbd_tcon		=	smb2_get_ksmbd_tcon,
	.is_sign_req		=	smb2_is_sign_req,
	.check_sign_req		=	smb3_check_sign_req,
	.set_sign_rsp		=	smb3_set_sign_rsp,
	.generate_signingkey	=	ksmbd_gen_smb311_signingkey,
	.generate_encryptionkey	=	ksmbd_gen_smb311_encryptionkey,
	.is_transform_hdr	=	smb3_is_transform_hdr,
	.decrypt_req		=	smb3_decrypt_req,
	.encrypt_resp		=	smb3_encrypt_resp
};

static struct smb_version_cmds smb2_0_server_cmds[NUMBER_OF_SMB2_COMMANDS] = {
	[SMB2_NEGOTIATE_HE]	=	{ .proc = smb2_negotiate_request, },
	[SMB2_SESSION_SETUP_HE] =	{ .proc = smb2_sess_setup, },
	[SMB2_TREE_CONNECT_HE]  =	{ .proc = smb2_tree_connect,},
	[SMB2_TREE_DISCONNECT_HE]  =	{ .proc = smb2_tree_disconnect,},
	[SMB2_LOGOFF_HE]	=	{ .proc = smb2_session_logoff,},
	[SMB2_CREATE_HE]	=	{ .proc = smb2_open},
	[SMB2_QUERY_INFO_HE]	=	{ .proc = smb2_query_info},
	[SMB2_QUERY_DIRECTORY_HE] =	{ .proc = smb2_query_dir},
	[SMB2_CLOSE_HE]		=	{ .proc = smb2_close},
	[SMB2_ECHO_HE]		=	{ .proc = smb2_echo},
	[SMB2_SET_INFO_HE]      =       { .proc = smb2_set_info},
	[SMB2_READ_HE]		=	{ .proc = smb2_read},
	[SMB2_WRITE_HE]		=	{ .proc = smb2_write},
	[SMB2_FLUSH_HE]		=	{ .proc = smb2_flush},
	[SMB2_CANCEL_HE]	=	{ .proc = smb2_cancel},
	[SMB2_LOCK_HE]		=	{ .proc = smb2_lock},
	[SMB2_IOCTL_HE]		=	{ .proc = smb2_ioctl},
	[SMB2_OPLOCK_BREAK_HE]	=	{ .proc = smb2_oplock_break},
	[SMB2_CHANGE_NOTIFY_HE]	=	{ .proc = smb2_notify},
};

/**
 * init_smb3_11_server() - initialize a smb server connection with smb3.11
 *			command dispatcher
 * @conn:	connection instance
 */
int init_smb3_11_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb311_server_values;
	conn->ops = &smb3_11_server_ops;
	conn->cmds = smb2_0_server_cmds;
	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);
	conn->signing_algorithm = SIGNING_ALG_AES_CMAC_LE;

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_LEASES)
		conn->vals->capabilities |= SMB2_GLOBAL_CAP_LEASING |
			SMB2_GLOBAL_CAP_DIRECTORY_LEASING;

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)
		conn->vals->capabilities |= SMB2_GLOBAL_CAP_MULTI_CHANNEL;

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE)
		conn->vals->capabilities |= SMB2_GLOBAL_CAP_PERSISTENT_HANDLES;

	INIT_LIST_HEAD(&conn->preauth_sess_table);
	return 0;
}

</document_content>
</document>
<document index="12">
<source>./kernel/fs/smb/server/smb2pdu.c</source>
<document_content>
#define WORK_BUFFERS(w, rq, rs)	__wbuf((w), (void **)&(rq), (void **)&(rs))

/**
 * smb2_set_err_rsp() - set error response code on smb response
 * @work:       smb work containing response buffer
 */
void smb2_set_err_rsp(struct ksmbd_work *work)
{
        struct smb2_err_rsp *err_rsp;

        if (work->next_smb2_rcv_hdr_off)
                err_rsp = ksmbd_resp_buf_next(work);
        else
                err_rsp = smb2_get_msg(work->response_buf);

        if (err_rsp->hdr.Status != STATUS_STOPPED_ON_SYMLINK) {
                int err;

                err_rsp->StructureSize = SMB2_ERROR_STRUCTURE_SIZE2_LE;
                err_rsp->ErrorContextCount = 0;
                err_rsp->Reserved = 0;
                err_rsp->ByteCount = 0;
                err_rsp->ErrorData[0] = 0;
                err = ksmbd_iov_pin_rsp(work, (void *)err_rsp,
                                        __SMB2_HEADER_STRUCTURE_SIZE +
                                                SMB2_ERROR_STRUCTURE_SIZE2);
                if (err)
                        work->send_no_response = 1;
        }
}

struct channel *lookup_chann_list(struct ksmbd_session *sess, struct ksmbd_conn *conn)
{
        return xa_load(&sess->ksmbd_chann_list, (long)conn);
}

/**
 * smb3_encryption_negotiated() - checks if server and client agreed on enabling encryption
 * @conn:       smb connection
 *
 * Return:      true if connection should be encrypted, else false
 */
bool smb3_encryption_negotiated(struct ksmbd_conn *conn)
{
        if (!conn->ops->generate_encryptionkey)
                return false;

        /*
         * SMB 3.0 and 3.0.2 dialects use the SMB2_GLOBAL_CAP_ENCRYPTION flag.
         * SMB 3.1.1 uses the cipher_type field.
         */
        return (conn->vals->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION) ||
            conn->cipher_type;
}

/**
 * smb2_check_user_session() - check for valid session for a user
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_check_user_session(struct ksmbd_work *work)
{
	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);
	struct ksmbd_conn *conn = work->conn;
	unsigned int cmd = le16_to_cpu(req_hdr->Command);
	unsigned long long sess_id;

	/*
	 * SMB2_ECHO, SMB2_NEGOTIATE, SMB2_SESSION_SETUP command do not
	 * require a session id, so no need to validate user session's for
	 * these commands.
	 */
	if (cmd == SMB2_ECHO_HE || cmd == SMB2_NEGOTIATE_HE ||
	    cmd == SMB2_SESSION_SETUP_HE)
		return 0;

	if (!ksmbd_conn_good(conn))
		return -EIO;

	sess_id = le64_to_cpu(req_hdr->SessionId);

	/*
	 * If request is not the first in Compound request,
	 * Just validate session id in header with work->sess->id.
	 */
	if (work->next_smb2_rcv_hdr_off) {
		if (!work->sess) {
			pr_err("The first operation in the compound does not have sess\n");
			return -EINVAL;
		}
		if (sess_id != ULLONG_MAX && work->sess->id != sess_id) {
			pr_err("session id(%llu) is different with the first operation(%lld)\n",
					sess_id, work->sess->id);
			return -EINVAL;
		}
		return 1;
	}

	/* Check for validity of user session */
	work->sess = ksmbd_session_lookup_all(conn, sess_id);
	if (work->sess)
		return 1;
	ksmbd_debug(SMB, "Invalid user session, Uid %llu\n", sess_id);
	return -ENOENT;
}

static int alloc_preauth_hash(struct ksmbd_session *sess,
			      struct ksmbd_conn *conn)
{
	if (sess->Preauth_HashValue)
		return 0;

	if (!conn->preauth_info)
		return -ENOMEM;

	sess->Preauth_HashValue = kmemdup(conn->preauth_info->Preauth_HashValue,
					  PREAUTH_HASHVALUE_SIZE, KSMBD_DEFAULT_GFP);
	if (!sess->Preauth_HashValue)
		return -ENOMEM;

	return 0;
}

static int generate_preauth_hash(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	u8 *preauth_hash;

	if (conn->dialect != SMB311_PROT_ID)
		return 0;

	if (conn->binding) {
		struct preauth_session *preauth_sess;

		preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
		if (!preauth_sess) {
			preauth_sess = ksmbd_preauth_session_alloc(conn, sess->id);
			if (!preauth_sess)
				return -ENOMEM;
		}

		preauth_hash = preauth_sess->Preauth_HashValue;
	} else {
		if (!sess->Preauth_HashValue)
			if (alloc_preauth_hash(sess, conn))
				return -ENOMEM;
		preauth_hash = sess->Preauth_HashValue;
	}

	ksmbd_gen_preauth_integrity_hash(conn, work->request_buf, preauth_hash);
	return 0;
}

static int decode_negotiation_token(struct ksmbd_conn *conn,
				    struct negotiate_message *negblob,
				    size_t sz)
{
	if (!conn->use_spnego)
		return -EINVAL;

	if (ksmbd_decode_negTokenInit((char *)negblob, sz, conn)) {
		if (ksmbd_decode_negTokenTarg((char *)negblob, sz, conn)) {
			conn->auth_mechs |= KSMBD_AUTH_NTLMSSP;
			conn->preferred_auth_mech = KSMBD_AUTH_NTLMSSP;
			conn->use_spnego = false;
		}
	}
	return 0;
}

static int krb5_authenticate(struct ksmbd_work *work,
			     struct smb2_sess_setup_req *req,
			     struct smb2_sess_setup_rsp *rsp)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	char *in_blob, *out_blob;
	struct channel *chann = NULL;
	u64 prev_sess_id;
	int in_len, out_len;
	int retval;

	in_blob = (char *)&req->hdr.ProtocolId +
		le16_to_cpu(req->SecurityBufferOffset);
	in_len = le16_to_cpu(req->SecurityBufferLength);
	out_blob = (char *)&rsp->hdr.ProtocolId +
		le16_to_cpu(rsp->SecurityBufferOffset);
	out_len = work->response_sz -
		(le16_to_cpu(rsp->SecurityBufferOffset) + 4);

	/* Check previous session */
	prev_sess_id = le64_to_cpu(req->PreviousSessionId);
	if (prev_sess_id && prev_sess_id != sess->id)
		destroy_previous_session(conn, sess->user, prev_sess_id);

	if (sess->state == SMB2_SESSION_VALID)
		ksmbd_free_user(sess->user);

	retval = ksmbd_krb5_authenticate(sess, in_blob, in_len,
					 out_blob, &out_len);
	if (retval) {
		ksmbd_debug(SMB, "krb5 authentication failed\n");
		return -EINVAL;
	}
	rsp->SecurityBufferLength = cpu_to_le16(out_len);

	if ((conn->sign || server_conf.enforced_signing) ||
	    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
		sess->sign = true;

	if (smb3_encryption_negotiated(conn)) {
		retval = conn->ops->generate_encryptionkey(conn, sess);
		if (retval) {
			ksmbd_debug(SMB,
				    "SMB3 encryption key generation failed\n");
			return -EINVAL;
		}
		sess->enc = true;
		if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION)
			rsp->SessionFlags = SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
		sess->sign = false;
	}

	if (conn->dialect >= SMB30_PROT_ID) {
		chann = lookup_chann_list(sess, conn);
		if (!chann) {
			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
			if (!chann)
				return -ENOMEM;

			chann->conn = conn;
			xa_store(&sess->ksmbd_chann_list, (long)conn, chann, KSMBD_DEFAULT_GFP);
		}
	}

	if (conn->ops->generate_signingkey) {
		retval = conn->ops->generate_signingkey(sess, conn);
		if (retval) {
			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
			return -EINVAL;
		}
	}

	if (!ksmbd_conn_lookup_dialect(conn)) {
		pr_err("fail to verify the dialect\n");
		return -ENOENT;
	}
	return 0;
}

static int ntlm_negotiate(struct ksmbd_work *work,
                          struct negotiate_message *negblob,
                          size_t negblob_len, struct smb2_sess_setup_rsp *rsp)
{
        struct challenge_message *chgblob;
        unsigned char *spnego_blob = NULL;
        u16 spnego_blob_len;
        char *neg_blob;
        int sz, rc;

        ksmbd_debug(SMB, "negotiate phase\n");
        rc = ksmbd_decode_ntlmssp_neg_blob(negblob, negblob_len, work->conn);
        if (rc)
                return rc;

        sz = le16_to_cpu(rsp->SecurityBufferOffset);
        chgblob = (struct challenge_message *)rsp->Buffer;
        memset(chgblob, 0, sizeof(struct challenge_message));

        if (!work->conn->use_spnego) {
                sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, work->conn);
                if (sz < 0)
                        return -ENOMEM;

                rsp->SecurityBufferLength = cpu_to_le16(sz);
                return 0;
        }

        sz = sizeof(struct challenge_message);
        sz += (strlen(ksmbd_netbios_name()) * 2 + 1 + 4) * 6;

        neg_blob = kzalloc(sz, KSMBD_DEFAULT_GFP);
        if (!neg_blob)
                return -ENOMEM;

        chgblob = (struct challenge_message *)neg_blob;
        sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, work->conn);
        if (sz < 0) {
                rc = -ENOMEM;
                goto out;
        }

        rc = build_spnego_ntlmssp_neg_blob(&spnego_blob, &spnego_blob_len,
                                           neg_blob, sz);
        if (rc) {
                rc = -ENOMEM;
                goto out;
        }

        memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
        rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);

out:
        kfree(spnego_blob);
        kfree(neg_blob);
        return rc;
}

static struct authenticate_message *user_authblob(struct ksmbd_conn *conn,
                                                  struct smb2_sess_setup_req *req)
{
        int sz;

        if (conn->use_spnego && conn->mechToken)
                return (struct authenticate_message *)conn->mechToken;

        sz = le16_to_cpu(req->SecurityBufferOffset);
        return (struct authenticate_message *)((char *)&req->hdr.ProtocolId
                                               + sz);
}

static struct ksmbd_user *session_user(struct ksmbd_conn *conn,
                                       struct smb2_sess_setup_req *req)
{
        struct authenticate_message *authblob;
        struct ksmbd_user *user;
        char *name;
        unsigned int name_off, name_len, secbuf_len;

        if (conn->use_spnego && conn->mechToken)
                secbuf_len = conn->mechTokenLen;
        else
                secbuf_len = le16_to_cpu(req->SecurityBufferLength);
        if (secbuf_len < sizeof(struct authenticate_message)) {
                ksmbd_debug(SMB, "blob len %d too small\n", secbuf_len);
                return NULL;
        }
        authblob = user_authblob(conn, req);
        name_off = le32_to_cpu(authblob->UserName.BufferOffset);
        name_len = le16_to_cpu(authblob->UserName.Length);

        if (secbuf_len < (u64)name_off + name_len)
                return NULL;

        name = smb_strndup_from_utf16((const char *)authblob + name_off,
                                      name_len,
                                      true,
                                      conn->local_nls);
        if (IS_ERR(name)) {
                pr_err("cannot allocate memory\n");
                return NULL;
        }

        ksmbd_debug(SMB, "session setup request for user %s\n", name);
        user = ksmbd_login_user(name);
        kfree(name);
        return user;
}

/**
 * ksmbd_auth_ntlmv2() - NTLMv2 authentication handler
 * @conn:               connection
 * @sess:               session of connection
 * @ntlmv2:             NTLMv2 challenge response
 * @blen:               NTLMv2 blob length
 * @domain_name:        domain name
 * @cryptkey:           session crypto key
 *
 * Return:      0 on success, error number on error
 */
int ksmbd_auth_ntlmv2(struct ksmbd_conn *conn, struct ksmbd_session *sess,
                      struct ntlmv2_resp *ntlmv2, int blen, char *domain_name,
                      char *cryptkey)
{
        char ntlmv2_hash[CIFS_ENCPWD_SIZE];
        char ntlmv2_rsp[CIFS_HMAC_MD5_HASH_SIZE];
        struct ksmbd_crypto_ctx *ctx = NULL;
        char *construct = NULL;
        int rc, len;

        rc = calc_ntlmv2_hash(conn, sess, ntlmv2_hash, domain_name);
        if (rc) {
                ksmbd_debug(AUTH, "could not get v2 hash rc %d\n", rc);
                goto out;
        }

        ctx = ksmbd_crypto_ctx_find_hmacmd5();
        if (!ctx) {
                ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");
                return -ENOMEM;
        }

        rc = crypto_shash_setkey(CRYPTO_HMACMD5_TFM(ctx),
                                 ntlmv2_hash,
                                 CIFS_HMAC_MD5_HASH_SIZE);
        if (rc) {
                ksmbd_debug(AUTH, "Could not set NTLMV2 Hash as a key\n");
                goto out;
        }

        rc = crypto_shash_init(CRYPTO_HMACMD5(ctx));
        if (rc) {
                ksmbd_debug(AUTH, "Could not init hmacmd5\n");
                goto out;
        }

        len = CIFS_CRYPTO_KEY_SIZE + blen;
        construct = kzalloc(len, KSMBD_DEFAULT_GFP);
        if (!construct) {
                rc = -ENOMEM;
                goto out;
        }

        memcpy(construct, cryptkey, CIFS_CRYPTO_KEY_SIZE);
        memcpy(construct + CIFS_CRYPTO_KEY_SIZE, &ntlmv2->blob_signature, blen);

        rc = crypto_shash_update(CRYPTO_HMACMD5(ctx), construct, len);
        if (rc) {
                ksmbd_debug(AUTH, "Could not update with response\n");
                goto out;
        }

        rc = crypto_shash_final(CRYPTO_HMACMD5(ctx), ntlmv2_rsp);
        if (rc) {
                ksmbd_debug(AUTH, "Could not generate md5 hash\n");
                goto out;
        }
        ksmbd_release_crypto_ctx(ctx);
        ctx = NULL;

        rc = ksmbd_gen_sess_key(sess, ntlmv2_hash, ntlmv2_rsp);
        if (rc) {
                ksmbd_debug(AUTH, "Could not generate sess key\n");
                goto out;
        }

        if (memcmp(ntlmv2->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE) != 0)
                rc = -EINVAL;
out:
        if (ctx)
                ksmbd_release_crypto_ctx(ctx);
        kfree(construct);
        return rc;
}

/**
 * ksmbd_decode_ntlmssp_auth_blob() - helper function to construct
 * authenticate blob
 * @authblob:   authenticate blob source pointer
 * @blob_len:   length of the @authblob message
 * @conn:       connection
 * @sess:       session of connection
 *
 * Return:      0 on success, error number on error
 */
int ksmbd_decode_ntlmssp_auth_blob(struct authenticate_message *authblob,
                                   int blob_len, struct ksmbd_conn *conn,
                                   struct ksmbd_session *sess)
{
        char *domain_name;
        unsigned int nt_off, dn_off;
        unsigned short nt_len, dn_len;
        int ret;

        if (blob_len < sizeof(struct authenticate_message)) {
                ksmbd_debug(AUTH, "negotiate blob len %d too small\n",
                            blob_len);
                return -EINVAL;
        }

        if (memcmp(authblob->Signature, "NTLMSSP", 8)) {
                ksmbd_debug(AUTH, "blob signature incorrect %s\n",
                            authblob->Signature);
                return -EINVAL;
        }

        nt_off = le32_to_cpu(authblob->NtChallengeResponse.BufferOffset);
        nt_len = le16_to_cpu(authblob->NtChallengeResponse.Length);
        dn_off = le32_to_cpu(authblob->DomainName.BufferOffset);
        dn_len = le16_to_cpu(authblob->DomainName.Length);

        if (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len ||
            nt_len < CIFS_ENCPWD_SIZE)
                return -EINVAL;

        /* TODO : use domain name that imported from configuration file */
        domain_name = smb_strndup_from_utf16((const char *)authblob + dn_off,
                                             dn_len, true, conn->local_nls);
        if (IS_ERR(domain_name))
                return PTR_ERR(domain_name);

        /* process NTLMv2 authentication */
        ksmbd_debug(AUTH, "decode_ntlmssp_authenticate_blob dname%s\n",
                    domain_name);
        ret = ksmbd_auth_ntlmv2(conn, sess,
                                (struct ntlmv2_resp *)((char *)authblob + nt_off),
                                nt_len - CIFS_ENCPWD_SIZE,
                                domain_name, conn->ntlmssp.cryptkey);
        kfree(domain_name);

        /* The recovered secondary session key */
        if (conn->ntlmssp.client_flags & NTLMSSP_NEGOTIATE_KEY_XCH) {
                struct arc4_ctx *ctx_arc4;
                unsigned int sess_key_off, sess_key_len;

                sess_key_off = le32_to_cpu(authblob->SessionKey.BufferOffset);
                sess_key_len = le16_to_cpu(authblob->SessionKey.Length);

                if (blob_len < (u64)sess_key_off + sess_key_len)
                        return -EINVAL;

                if (sess_key_len > CIFS_KEY_SIZE)
                        return -EINVAL;

                ctx_arc4 = kmalloc(sizeof(*ctx_arc4), KSMBD_DEFAULT_GFP);
                if (!ctx_arc4)
                        return -ENOMEM;

                cifs_arc4_setkey(ctx_arc4, sess->sess_key,
                                 SMB2_NTLMV2_SESSKEY_SIZE);
                cifs_arc4_crypt(ctx_arc4, sess->sess_key,
                                (char *)authblob + sess_key_off, sess_key_len);
                kfree_sensitive(ctx_arc4);
        }

        return ret;
}

static int ntlm_authenticate(struct ksmbd_work *work,
                             struct smb2_sess_setup_req *req,
                             struct smb2_sess_setup_rsp *rsp)
{
        struct ksmbd_conn *conn = work->conn;
        struct ksmbd_session *sess = work->sess;
        struct channel *chann = NULL;
        struct ksmbd_user *user;
        u64 prev_id;
        int sz, rc;

        ksmbd_debug(SMB, "authenticate phase\n");
        if (conn->use_spnego) {
                unsigned char *spnego_blob;
                u16 spnego_blob_len;

                rc = build_spnego_ntlmssp_auth_blob(&spnego_blob,
                                                    &spnego_blob_len,
                                                    0);
                if (rc)
                        return -ENOMEM;

                memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
                rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);
                kfree(spnego_blob);
        }

        user = session_user(conn, req);
        if (!user) {
                ksmbd_debug(SMB, "Unknown user name or an error\n");
                return -EPERM;
        }

        /* Check for previous session */
        prev_id = le64_to_cpu(req->PreviousSessionId);
        if (prev_id && prev_id != sess->id)
                destroy_previous_session(conn, user, prev_id);

        if (sess->state == SMB2_SESSION_VALID) {
                /*
                 * Reuse session if anonymous try to connect
                 * on reauthetication.
                 */
                if (conn->binding == false && ksmbd_anonymous_user(user)) {
                        ksmbd_free_user(user);
                        return 0;
                }

                if (!ksmbd_compare_user(sess->user, user)) {
                        ksmbd_free_user(user);
                        return -EPERM;
                }
                ksmbd_free_user(user);
        } else {
                sess->user = user;
        }

        if (conn->binding == false && user_guest(sess->user)) {
                rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST_LE;
        } else {
                struct authenticate_message *authblob;

                authblob = user_authblob(conn, req);
                if (conn->use_spnego && conn->mechToken)
                        sz = conn->mechTokenLen;
                else
                        sz = le16_to_cpu(req->SecurityBufferLength);
                rc = ksmbd_decode_ntlmssp_auth_blob(authblob, sz, conn, sess);
                if (rc) {
                        set_user_flag(sess->user, KSMBD_USER_FLAG_BAD_PASSWORD);
                        ksmbd_debug(SMB, "authentication failed\n");
                        return -EPERM;
                }
        }

        /*
         * If session state is SMB2_SESSION_VALID, We can assume
         * that it is reauthentication. And the user/password
         * has been verified, so return it here.
         */
        if (sess->state == SMB2_SESSION_VALID) {
                if (conn->binding)
                        goto binding_session;
                return 0;
        }

        if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&
             (conn->sign || server_conf.enforced_signing)) ||
            (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
                sess->sign = true;

        if (smb3_encryption_negotiated(conn) &&
                        !(req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
                rc = conn->ops->generate_encryptionkey(conn, sess);
                if (rc) {
                        ksmbd_debug(SMB,
                                        "SMB3 encryption key generation failed\n");
                        return -EINVAL;
                }
                sess->enc = true;
                if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION)
                        rsp->SessionFlags = SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
                /*
                 * signing is disable if encryption is enable
                 * on this session
                 */
                sess->sign = false;
                        }

binding_session:
        if (conn->dialect >= SMB30_PROT_ID) {
                chann = lookup_chann_list(sess, conn);
                if (!chann) {
                        chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
                        if (!chann)
                                return -ENOMEM;

                        chann->conn = conn;
                        xa_store(&sess->ksmbd_chann_list, (long)conn, chann, KSMBD_DEFAULT_GFP);
                }
        }

        if (conn->ops->generate_signingkey) {
                rc = conn->ops->generate_signingkey(sess, conn);
                if (rc) {
                        ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
                        return -EINVAL;
                }
        }

        if (!ksmbd_conn_lookup_dialect(conn)) {
                pr_err("fail to verify the dialect\n");
                return -ENOENT;
        }
        return 0;
}

int smb2_sess_setup(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_sess_setup_req *req;
	struct smb2_sess_setup_rsp *rsp;
	struct ksmbd_session *sess;
	struct negotiate_message *negblob;
	unsigned int negblob_len, negblob_off;
	int rc = 0;

	ksmbd_debug(SMB, "Received smb2 session setup request\n");

	if (!ksmbd_conn_need_setup(conn) && !ksmbd_conn_good(conn)) {
		work->send_no_response = 1;
		return rc;
	}

	WORK_BUFFERS(work, req, rsp);

	rsp->StructureSize = cpu_to_le16(9);
	rsp->SessionFlags = 0;
	rsp->SecurityBufferOffset = cpu_to_le16(72);
	rsp->SecurityBufferLength = 0;

	ksmbd_conn_lock(conn);
	if (!req->hdr.SessionId) {
		sess = ksmbd_smb2_session_create();
		if (!sess) {
			rc = -ENOMEM;
			goto out_err;
		}
		rsp->hdr.SessionId = cpu_to_le64(sess->id);
		rc = ksmbd_session_register(conn, sess);
		if (rc)
			goto out_err;

		conn->binding = false;
	} else if (conn->dialect >= SMB30_PROT_ID &&
		   (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		   req->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
		u64 sess_id = le64_to_cpu(req->hdr.SessionId);

		sess = ksmbd_session_lookup_slowpath(sess_id);
		if (!sess) {
			rc = -ENOENT;
			goto out_err;
		}

		if (conn->dialect != sess->dialect) {
			rc = -EINVAL;
			goto out_err;
		}

		if (!(req->hdr.Flags & SMB2_FLAGS_SIGNED)) {
			rc = -EINVAL;
			goto out_err;
		}

		if (strncmp(conn->ClientGUID, sess->ClientGUID,
			    SMB2_CLIENT_GUID_SIZE)) {
			rc = -ENOENT;
			goto out_err;
		}

		if (sess->state == SMB2_SESSION_IN_PROGRESS) {
			rc = -EACCES;
			goto out_err;
		}

		if (sess->state == SMB2_SESSION_EXPIRED) {
			rc = -EFAULT;
			goto out_err;
		}

		if (ksmbd_conn_need_reconnect(conn)) {
			rc = -EFAULT;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		if (is_ksmbd_session_in_connection(conn, sess_id)) {
			rc = -EACCES;
			goto out_err;
		}

		if (user_guest(sess->user)) {
			rc = -EOPNOTSUPP;
			goto out_err;
		}

		conn->binding = true;
	} else if ((conn->dialect < SMB30_PROT_ID ||
		    server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		sess = NULL;
		rc = -EACCES;
		goto out_err;
	} else {
		sess = ksmbd_session_lookup(conn,
					    le64_to_cpu(req->hdr.SessionId));
		if (!sess) {
			rc = -ENOENT;
			goto out_err;
		}

		if (sess->state == SMB2_SESSION_EXPIRED) {
			rc = -EFAULT;
			goto out_err;
		}

		if (ksmbd_conn_need_reconnect(conn)) {
			rc = -EFAULT;
			sess = NULL;
			goto out_err;
		}

		conn->binding = false;
	}
	work->sess = sess;

	negblob_off = le16_to_cpu(req->SecurityBufferOffset);
	negblob_len = le16_to_cpu(req->SecurityBufferLength);
	if (negblob_off < offsetof(struct smb2_sess_setup_req, Buffer)) {
		rc = -EINVAL;
		goto out_err;
	}

	negblob = (struct negotiate_message *)((char *)&req->hdr.ProtocolId +
			negblob_off);

	if (decode_negotiation_token(conn, negblob, negblob_len) == 0) {
		if (conn->mechToken) {
			negblob = (struct negotiate_message *)conn->mechToken;
			negblob_len = conn->mechTokenLen;
		}
	}

	if (negblob_len < offsetof(struct negotiate_message, NegotiateFlags)) {
		rc = -EINVAL;
		goto out_err;
	}

	if (server_conf.auth_mechs & conn->auth_mechs) {
		rc = generate_preauth_hash(work);
		if (rc)
			goto out_err;

		if (conn->preferred_auth_mech &
				(KSMBD_AUTH_KRB5 | KSMBD_AUTH_MSKRB5)) {
			rc = krb5_authenticate(work, req, rsp);
			if (rc) {
				rc = -EINVAL;
				goto out_err;
			}

			if (!ksmbd_conn_need_reconnect(conn)) {
				ksmbd_conn_set_good(conn);
				sess->state = SMB2_SESSION_VALID;
			}
			kfree(sess->Preauth_HashValue);
			sess->Preauth_HashValue = NULL;
		} else if (conn->preferred_auth_mech == KSMBD_AUTH_NTLMSSP) {
			if (negblob->MessageType == NtLmNegotiate) {
				rc = ntlm_negotiate(work, negblob, negblob_len, rsp);
				if (rc)
					goto out_err;
				rsp->hdr.Status =
					STATUS_MORE_PROCESSING_REQUIRED;
			} else if (negblob->MessageType == NtLmAuthenticate) {
				rc = ntlm_authenticate(work, req, rsp);
				if (rc)
					goto out_err;

				if (!ksmbd_conn_need_reconnect(conn)) {
					ksmbd_conn_set_good(conn);
					sess->state = SMB2_SESSION_VALID;
				}
				if (conn->binding) {
					struct preauth_session *preauth_sess;

					preauth_sess =
						ksmbd_preauth_session_lookup(conn, sess->id);
					if (preauth_sess) {
						list_del(&preauth_sess->preauth_entry);
						kfree(preauth_sess);
					}
				}
				kfree(sess->Preauth_HashValue);
				sess->Preauth_HashValue = NULL;
			} else {
				pr_info_ratelimited("Unknown NTLMSSP message type : 0x%x\n",
						le32_to_cpu(negblob->MessageType));
				rc = -EINVAL;
			}
		} else {
			/* TODO: need one more negotiation */
			pr_err("Not support the preferred authentication\n");
			rc = -EINVAL;
		}
	} else {
		pr_err("Not support authentication\n");
		rc = -EINVAL;
	}

out_err:
	if (rc == -EINVAL)
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	else if (rc == -ENOENT)
		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
	else if (rc == -EACCES)
		rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
	else if (rc == -EFAULT)
		rsp->hdr.Status = STATUS_NETWORK_SESSION_EXPIRED;
	else if (rc == -ENOMEM)
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
	else if (rc == -EOPNOTSUPP)
		rsp->hdr.Status = STATUS_NOT_SUPPORTED;
	else if (rc)
		rsp->hdr.Status = STATUS_LOGON_FAILURE;

	if (conn->use_spnego && conn->mechToken) {
		kfree(conn->mechToken);
		conn->mechToken = NULL;
	}

	if (rc < 0) {
		/*
		 * SecurityBufferOffset should be set to zero
		 * in session setup error response.
		 */
		rsp->SecurityBufferOffset = 0;

		if (sess) {
			bool try_delay = false;

			/*
			 * To avoid dictionary attacks (repeated session setups rapidly sent) to
			 * connect to server, ksmbd make a delay of a 5 seconds on session setup
			 * failure to make it harder to send enough random connection requests
			 * to break into a server.
			 */
			if (sess->user && sess->user->flags & KSMBD_USER_FLAG_DELAY_SESSION)
				try_delay = true;

			sess->last_active = jiffies;
			sess->state = SMB2_SESSION_EXPIRED;
			ksmbd_user_session_put(sess);
			work->sess = NULL;
			if (try_delay) {
				ksmbd_conn_set_need_reconnect(conn);
				ssleep(5);
				ksmbd_conn_set_need_setup(conn);
			}
		}
		smb2_set_err_rsp(work);
	} else {
		unsigned int iov_len;

		if (rsp->SecurityBufferLength)
			iov_len = offsetof(struct smb2_sess_setup_rsp, Buffer) +
				le16_to_cpu(rsp->SecurityBufferLength);
		else
			iov_len = sizeof(struct smb2_sess_setup_rsp);
		rc = ksmbd_iov_pin_rsp(work, rsp, iov_len);
		if (rc)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
	}

	ksmbd_conn_unlock(conn);
	return rc;
}


</document_content>
</document>
<document index="13">
<source>./kernel/fs/smb/server/smb2pdu.h</source>
<document_content>
/*
 * Get the body of the smb2 message excluding the 4 byte rfc1002 headers
 * from request/response buffer.
 */
static inline void *smb2_get_msg(void *buf)
{
        return buf + 4;
}



</document_content>
</document>
<document index="14">
<source>./kernel/fs/smb/server/smb_common.h</source>
<document_content>
static inline void inc_rfc1001_len(void *buf, int count)
{
        be32_add_cpu((__be32 *)buf, count);
}

static inline unsigned int get_rfc1002_len(void *buf)
{
        return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

</document_content>
</document>
<document index="15">
<source>./kernel/fs/smb/server/transport_ipc.c</source>
<document_content>
struct ksmbd_spnego_authen_response *
ksmbd_ipc_spnego_authen_request(const char *spnego_blob, int blob_len)
{
        struct ksmbd_ipc_msg *msg;
        struct ksmbd_spnego_authen_request *req;
        struct ksmbd_spnego_authen_response *resp;

        if (blob_len > KSMBD_IPC_MAX_PAYLOAD)
                return NULL;

        msg = ipc_msg_alloc(sizeof(struct ksmbd_spnego_authen_request) +
                        blob_len + 1);
        if (!msg)
                return NULL;

        msg->type = KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST;
        req = (struct ksmbd_spnego_authen_request *)msg->payload;
        req->handle = ksmbd_acquire_id(&ipc_ida);
        req->spnego_blob_len = blob_len;
        memcpy(req->spnego_blob, spnego_blob, blob_len);

        resp = ipc_msg_send_request(msg, req->handle);
        ipc_msg_handle_free(req->handle);
        ipc_msg_free(msg);
        return resp;
}

int ksmbd_ipc_logout_request(const char *account, int flags)
{
        struct ksmbd_ipc_msg *msg;
        struct ksmbd_logout_request *req;
        int ret;

        if (strlen(account) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)
                return -EINVAL;

        msg = ipc_msg_alloc(sizeof(struct ksmbd_logout_request));
        if (!msg)
                return -ENOMEM;

        msg->type = KSMBD_EVENT_LOGOUT_REQUEST;
        req = (struct ksmbd_logout_request *)msg->payload;
        req->account_flags = flags;
        strscpy(req->account, account, KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);

        ret = ipc_msg_send(msg);
        ipc_msg_free(msg);
        return ret;
}

struct ksmbd_login_response_ext *ksmbd_ipc_login_request_ext(const char *account)
{
        struct ksmbd_ipc_msg *msg;
        struct ksmbd_login_request *req;
        struct ksmbd_login_response_ext *resp;

        if (strlen(account) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)
                return NULL;

        msg = ipc_msg_alloc(sizeof(struct ksmbd_login_request));
        if (!msg)
                return NULL;

        msg->type = KSMBD_EVENT_LOGIN_REQUEST_EXT;
        req = (struct ksmbd_login_request *)msg->payload;
        req->handle = ksmbd_acquire_id(&ipc_ida);
        strscpy(req->account, account, KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);
        resp = ipc_msg_send_request(msg, req->handle);
        ipc_msg_handle_free(req->handle);
        ipc_msg_free(msg);
        return resp;
}

</document_content>
</document>
<document index="16">
<source>./kernel/fs/smb/server/transport_tcp.c</source>
<document_content>
/**
 * ksmbd_kthread_fn() - listen to new SMB connections and callback server
 * @p:		arguments to forker thread
 *
 * Return:	0 on success, error number otherwise
 */
static int ksmbd_kthread_fn(void *p)
{
	struct socket *client_sk = NULL;
	struct interface *iface = (struct interface *)p;
	int ret;

	while (!kthread_should_stop()) {
		mutex_lock(&iface->sock_release_lock);
		if (!iface->ksmbd_socket) {
			mutex_unlock(&iface->sock_release_lock);
			break;
		}
		ret = kernel_accept(iface->ksmbd_socket, &client_sk,
				    SOCK_NONBLOCK);
		mutex_unlock(&iface->sock_release_lock);
		if (ret) {
			if (ret == -EAGAIN)
				/* check for new connections every 100 msecs */
				schedule_timeout_interruptible(HZ / 10);
			continue;
		}

		if (server_conf.max_connections &&
		    atomic_inc_return(&active_num_conn) >= server_conf.max_connections) {
			pr_info_ratelimited("Limit the maximum number of connections(%u)\n",
					    atomic_read(&active_num_conn));
			atomic_dec(&active_num_conn);
			sock_release(client_sk);
			continue;
		}

		ksmbd_debug(CONN, "connect success: accepted new connection\n");
		client_sk->sk->sk_rcvtimeo = KSMBD_TCP_RECV_TIMEOUT;
		client_sk->sk->sk_sndtimeo = KSMBD_TCP_SEND_TIMEOUT;

		ksmbd_tcp_new_connection(client_sk);
	}

	ksmbd_debug(CONN, "releasing socket\n");
	return 0;
}

/**
 * ksmbd_tcp_run_kthread() - start forker thread
 * @iface: pointer to struct interface
 *
 * start forker thread(ksmbd/0) at module init time to listen
 * on port 445 for new SMB connection requests. It creates per connection
 * server threads(ksmbd/x)
 *
 * Return:	0 on success or error number
 */
static int ksmbd_tcp_run_kthread(struct interface *iface)
{
	int rc;
	struct task_struct *kthread;

	kthread = kthread_run(ksmbd_kthread_fn, (void *)iface, "ksmbd-%s",
			      iface->name);
	if (IS_ERR(kthread)) {
		rc = PTR_ERR(kthread);
		return rc;
	}
	iface->ksmbd_kthread = kthread;

	return 0;
}


/**
 * create_socket - create socket for ksmbd/0
 * @iface:      interface to bind the created socket to
 *
 * Return:	0 on success, error number otherwise
 */
static int create_socket(struct interface *iface)
{
	int ret;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct socket *ksmbd_socket;
	bool ipv4 = false;

	ret = sock_create(PF_INET6, SOCK_STREAM, IPPROTO_TCP, &ksmbd_socket);
	if (ret) {
		if (ret != -EAFNOSUPPORT)
			pr_err("Can't create socket for ipv6, fallback to ipv4: %d\n", ret);
		ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP,
				  &ksmbd_socket);
		if (ret) {
			pr_err("Can't create socket for ipv4: %d\n", ret);
			goto out_clear;
		}

		sin.sin_family = PF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		sin.sin_port = htons(server_conf.tcp_port);
		ipv4 = true;
	} else {
		sin6.sin6_family = PF_INET6;
		sin6.sin6_addr = in6addr_any;
		sin6.sin6_port = htons(server_conf.tcp_port);

		lock_sock(ksmbd_socket->sk);
		ksmbd_socket->sk->sk_ipv6only = false;
		release_sock(ksmbd_socket->sk);
	}

	ksmbd_tcp_nodelay(ksmbd_socket);
	ksmbd_tcp_reuseaddr(ksmbd_socket);

	ret = sock_setsockopt(ksmbd_socket,
			      SOL_SOCKET,
			      SO_BINDTODEVICE,
			      KERNEL_SOCKPTR(iface->name),
			      strlen(iface->name));
	if (ret != -ENODEV && ret < 0) {
		pr_err("Failed to set SO_BINDTODEVICE: %d\n", ret);
		goto out_error;
	}

	if (ipv4)
		ret = kernel_bind(ksmbd_socket, (struct sockaddr *)&sin,
				  sizeof(sin));
	else
		ret = kernel_bind(ksmbd_socket, (struct sockaddr *)&sin6,
				  sizeof(sin6));
	if (ret) {
		pr_err("Failed to bind socket: %d\n", ret);
		goto out_error;
	}

	ksmbd_socket->sk->sk_rcvtimeo = KSMBD_TCP_RECV_TIMEOUT;
	ksmbd_socket->sk->sk_sndtimeo = KSMBD_TCP_SEND_TIMEOUT;

	ret = kernel_listen(ksmbd_socket, KSMBD_SOCKET_BACKLOG);
	if (ret) {
		pr_err("Port listen() error: %d\n", ret);
		goto out_error;
	}

	iface->ksmbd_socket = ksmbd_socket;
	ret = ksmbd_tcp_run_kthread(iface);
	if (ret) {
		pr_err("Can't start ksmbd main kthread: %d\n", ret);
		goto out_error;
	}
	iface->state = IFACE_STATE_CONFIGURED;

	return 0;

out_error:
	tcp_destroy_socket(ksmbd_socket);
out_clear:
	iface->ksmbd_socket = NULL;
	return ret;
}


</document_content>
</document>
<document index="17">
<source>./kernel/fs/smb/server/unicode.c</source>
<document_content>
/*
 * smb_strtoUTF16() - Convert character string to unicode string
 * @to:         destination buffer
 * @from:       source buffer
 * @len:        destination buffer size (in bytes)
 * @codepage:   codepage to which characters should be converted
 *
 * Return:      string length after conversion
 */
int smb_strtoUTF16(__le16 *to, const char *from, int len,
                   const struct nls_table *codepage)
{
        int charlen;
        int i;
        wchar_t wchar_to; /* needed to quiet sparse */

        /* special case for utf8 to handle no plane0 chars */
        if (!strcmp(codepage->charset, "utf8")) {
                /*
                 * convert utf8 -> utf16, we assume we have enough space
                 * as caller should have assumed conversion does not overflow
                 * in destination len is length in wchar_t units (16bits)
                 */
                i  = utf8s_to_utf16s(from, len, UTF16_LITTLE_ENDIAN,
                                     (wchar_t *)to, len);

                /* if success terminate and exit */
                if (i >= 0)
                        goto success;
                /*
                 * if fails fall back to UCS encoding as this
                 * function should not return negative values
                 * currently can fail only if source contains
                 * invalid encoded characters
                 */
        }

        for (i = 0; len > 0 && *from; i++, from += charlen, len -= charlen) {
                charlen = codepage->char2uni(from, len, &wchar_to);
                if (charlen < 1) {
                        /* A question mark */
                        wchar_to = 0x003f;
                        charlen = 1;
                }
                put_unaligned_le16(wchar_to, &to[i]);
        }

success:
        put_unaligned_le16(0, &to[i]);
        return i;
}

/*
 * smb_strndup_from_utf16() - copy a string from wire format to the local
 *              codepage
 * @src:        source string
 * @maxlen:     don't walk past this many bytes in the source string
 * @is_unicode: is this a unicode string?
 * @codepage:   destination codepage
 *
 * Take a string given by the server, convert it to the local codepage and
 * put it in a new buffer. Returns a pointer to the new string or NULL on
 * error.
 *
 * Return:      destination string buffer or error ptr
 */
char *smb_strndup_from_utf16(const char *src, const int maxlen,
                             const bool is_unicode,
                             const struct nls_table *codepage)
{
        int len, ret;
        char *dst;

        if (is_unicode) {
                len = smb_utf16_bytes((__le16 *)src, maxlen, codepage);
                len += nls_nullsize(codepage);
                dst = kmalloc(len, KSMBD_DEFAULT_GFP);
                if (!dst)
                        return ERR_PTR(-ENOMEM);
                ret = smb_from_utf16(dst, (__le16 *)src, len, maxlen, codepage,
                                     false);
                if (ret < 0) {
                        kfree(dst);
                        return ERR_PTR(-EINVAL);
                }
        } else {
                len = strnlen(src, maxlen);
                len++;
                dst = kmalloc(len, KSMBD_DEFAULT_GFP);
                if (!dst)
                        return ERR_PTR(-ENOMEM);
                strscpy(dst, src, len);
        }

        return dst;
}

</document_content>
</document>
<document index="18">
<source>./kernel/fs/smb/server/vfs_cache.c</source>
<document_content>
int ksmbd_init_file_table(struct ksmbd_file_table *ft)
{
        ft->idr = kzalloc(sizeof(struct idr), KSMBD_DEFAULT_GFP);
        if (!ft->idr)
                return -ENOMEM;

        idr_init(ft->idr);
        rwlock_init(&ft->lock);
        return 0;
}

void ksmbd_destroy_file_table(struct ksmbd_file_table *ft)
{
        if (!ft->idr)
                return;

        __close_file_table_ids(ft, NULL, session_fd_check);
        idr_destroy(ft->idr);
        kfree(ft->idr);
        ft->idr = NULL;
}

void ksmbd_launch_ksmbd_durable_scavenger(void)
{
        if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))
                return;

        mutex_lock(&durable_scavenger_lock);
        if (durable_scavenger_running == true) {
                mutex_unlock(&durable_scavenger_lock);
                return;
        }

        durable_scavenger_running = true;

        server_conf.dh_task = kthread_run(ksmbd_durable_scavenger,
                                     (void *)NULL, "ksmbd-durable-scavenger");
        if (IS_ERR(server_conf.dh_task))
                pr_err("cannot start conn thread, err : %ld\n",
                       PTR_ERR(server_conf.dh_task));
        mutex_unlock(&durable_scavenger_lock);
}

</document_content>
</document>
<document index="19">
<source>./kernel/fs/smb/server/mgmt/user_config.c</source>
<document_content>
void ksmbd_free_user(struct ksmbd_user *user)
{
        ksmbd_ipc_logout_request(user->name, user->flags);
        kfree(user->sgid);
        kfree(user->name);
        kfree(user->passkey);
        kfree(user);
}

struct ksmbd_user *ksmbd_alloc_user(struct ksmbd_login_response *resp,
                struct ksmbd_login_response_ext *resp_ext)
{
        struct ksmbd_user *user;

        user = kmalloc(sizeof(struct ksmbd_user), KSMBD_DEFAULT_GFP);
        if (!user)
                return NULL;

        user->name = kstrdup(resp->account, KSMBD_DEFAULT_GFP);
        user->flags = resp->status;
        user->gid = resp->gid;
        user->uid = resp->uid;
        user->passkey_sz = resp->hash_sz;
        user->passkey = kmalloc(resp->hash_sz, KSMBD_DEFAULT_GFP);
        if (user->passkey)
                memcpy(user->passkey, resp->hash, resp->hash_sz);

        user->ngroups = 0;
        user->sgid = NULL;

        if (!user->name || !user->passkey)
                goto err_free;

        if (resp_ext) {
                if (resp_ext->ngroups > NGROUPS_MAX) {
                        pr_err("ngroups(%u) from login response exceeds max groups(%d)\n",
                                        resp_ext->ngroups, NGROUPS_MAX);
                        goto err_free;
                }

                user->sgid = kmemdup(resp_ext->____payload,
                                     resp_ext->ngroups * sizeof(gid_t),
                                     KSMBD_DEFAULT_GFP);
                if (!user->sgid)
                        goto err_free;

                user->ngroups = resp_ext->ngroups;
                ksmbd_debug(SMB, "supplementary groups : %d\n", user->ngroups);
        }

        return user;

err_free:
        kfree(user->name);
        kfree(user->passkey);
        kfree(user);
        return NULL;
}

struct ksmbd_user *ksmbd_login_user(const char *account)
{
        struct ksmbd_login_response *resp;
        struct ksmbd_login_response_ext *resp_ext = NULL;
        struct ksmbd_user *user = NULL;

        resp = ksmbd_ipc_login_request(account);
        if (!resp)
                return NULL;

        if (!(resp->status & KSMBD_USER_FLAG_OK))
                goto out;

        if (resp->status & KSMBD_USER_FLAG_EXTENSION)
                resp_ext = ksmbd_ipc_login_request_ext(account);

        user = ksmbd_alloc_user(resp, resp_ext);
out:
        kvfree(resp);
        return user;
}

</document_content>
</document>
<document index="20">
<source>./kernel/fs/smb/server/mgmt/user_config.h</source>
<document_content>
struct ksmbd_user {
        unsigned short          flags;

        unsigned int            uid;
        unsigned int            gid;

        char                    *name;

        size_t                  passkey_sz;
        char                    *passkey;
        int                     ngroups;
        gid_t                   *sgid;
};

static inline bool user_guest(struct ksmbd_user *user)
{
        return user->flags & KSMBD_USER_FLAG_GUEST_ACCOUNT;
}

static inline void set_user_flag(struct ksmbd_user *user, int flag)
{
        user->flags |= flag;
}

</document_content>
</document>
<document index="21">
<source>./kernel/fs/smb/server/mgmt/user_session.c</source>
<document_content>
struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,
                                                    u64 sess_id)
{
        struct preauth_session *sess;

        sess = kmalloc(sizeof(struct preauth_session), KSMBD_DEFAULT_GFP);
        if (!sess)
                return NULL;

        sess->id = sess_id;
        memcpy(sess->Preauth_HashValue, conn->preauth_info->Preauth_HashValue,
               PREAUTH_HASHVALUE_SIZE);
        list_add(&sess->preauth_entry, &conn->preauth_sess_table);

        return sess;
}

void ksmbd_user_session_get(struct ksmbd_session *sess)
{
        atomic_inc(&sess->refcnt);
}

static void ksmbd_expire_session(struct ksmbd_conn *conn)
{
        unsigned long id;
        struct ksmbd_session *sess;

        down_write(&sessions_table_lock);
        down_write(&conn->session_lock);
        xa_for_each(&conn->sessions, id, sess) {
                if (atomic_read(&sess->refcnt) <= 1 &&
                    (sess->state != SMB2_SESSION_VALID ||
                     time_after(jiffies,
                               sess->last_active + SMB2_SESSION_TIMEOUT))) {
                        xa_erase(&conn->sessions, sess->id);
                        hash_del(&sess->hlist);
                        ksmbd_session_destroy(sess);
                        continue;
                }
        }
        up_write(&conn->session_lock);
        up_write(&sessions_table_lock);
}

void ksmbd_session_destroy(struct ksmbd_session *sess)
{
        if (!sess)
                return;

        if (sess->user)
                ksmbd_free_user(sess->user);

        ksmbd_tree_conn_session_logoff(sess);
        ksmbd_destroy_file_table(&sess->file_table);
        ksmbd_launch_ksmbd_durable_scavenger();
        ksmbd_session_rpc_clear_list(sess);
        free_channel_list(sess);
        kfree(sess->Preauth_HashValue);
        ksmbd_release_id(&session_ida, sess->id);
        kfree(sess);
}

static int __init_smb2_session(struct ksmbd_session *sess)
{
        int id = ksmbd_acquire_smb2_uid(&session_ida);

        if (id < 0)
                return -EINVAL;
        sess->id = id;
        return 0;
}

static struct ksmbd_session *__session_create(int protocol)
{
        struct ksmbd_session *sess;
        int ret;

        if (protocol != CIFDS_SESSION_FLAG_SMB2)
                return NULL;

        sess = kzalloc(sizeof(struct ksmbd_session), KSMBD_DEFAULT_GFP);
        if (!sess)
                return NULL;

        if (ksmbd_init_file_table(&sess->file_table))
                goto error;

        sess->last_active = jiffies;
        sess->state = SMB2_SESSION_IN_PROGRESS;
        set_session_flag(sess, protocol);
        xa_init(&sess->tree_conns);
        xa_init(&sess->ksmbd_chann_list);
        xa_init(&sess->rpc_handle_list);
        sess->sequence_number = 1;
        rwlock_init(&sess->tree_conns_lock);
        atomic_set(&sess->refcnt, 2);

        ret = __init_smb2_session(sess);
        if (ret)
                goto error;

        ida_init(&sess->tree_conn_ida);

        down_write(&sessions_table_lock);
        hash_add(sessions_table, &sess->hlist, sess->id);
        up_write(&sessions_table_lock);

        return sess;

error:
        ksmbd_session_destroy(sess);
        return NULL;
}

struct ksmbd_session *ksmbd_smb2_session_create(void)
{
        return __session_create(CIFDS_SESSION_FLAG_SMB2);
}

int ksmbd_session_register(struct ksmbd_conn *conn,
                           struct ksmbd_session *sess)
{
        sess->dialect = conn->dialect;
        memcpy(sess->ClientGUID, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);
        ksmbd_expire_session(conn);
        return xa_err(xa_store(&conn->sessions, sess->id, sess, KSMBD_DEFAULT_GFP));
}

struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
                                           unsigned long long id)
{
        struct ksmbd_session *sess;

        down_read(&conn->session_lock);
        sess = xa_load(&conn->sessions, id);
        if (sess) {
                sess->last_active = jiffies;
                ksmbd_user_session_get(sess);
        }
        up_read(&conn->session_lock);
        return sess;
}

struct ksmbd_session *__session_lookup(unsigned long long id)
{
        struct ksmbd_session *sess;

        hash_for_each_possible(sessions_table, sess, hlist, id) {
                if (id == sess->id) {
                        sess->last_active = jiffies;
                        return sess;
                }
        }
        return NULL;
}

struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id)
{
        struct ksmbd_session *sess;

        down_read(&sessions_table_lock);
        sess = __session_lookup(id);
        if (sess)
                ksmbd_user_session_get(sess);
        up_read(&sessions_table_lock);

        return sess;
}

void ksmbd_user_session_put(struct ksmbd_session *sess)
{
        if (!sess)
                return;

        if (atomic_read(&sess->refcnt) <= 0)
                WARN_ON(1);
        else if (atomic_dec_and_test(&sess->refcnt))
                ksmbd_session_destroy(sess);
}

bool is_ksmbd_session_in_connection(struct ksmbd_conn *conn,
                                   unsigned long long id)
{
        struct ksmbd_session *sess;

        down_read(&conn->session_lock);
        sess = xa_load(&conn->sessions, id);
        if (sess) {
                up_read(&conn->session_lock);
                return true;
        }
        up_read(&conn->session_lock);

        return false;
}

static bool ksmbd_preauth_session_id_match(struct preauth_session *sess,
                                           unsigned long long id)
{
        return sess->id == id;
}

struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,
                                                     unsigned long long id)
{
        struct preauth_session *sess = NULL;

        list_for_each_entry(sess, &conn->preauth_sess_table, preauth_entry) {
                if (ksmbd_preauth_session_id_match(sess, id))
                        return sess;
        }
        return NULL;
}

void destroy_previous_session(struct ksmbd_conn *conn,
                              struct ksmbd_user *user, u64 id)
{
        struct ksmbd_session *prev_sess;
        struct ksmbd_user *prev_user;
        int err;

        down_write(&sessions_table_lock);
        down_write(&conn->session_lock);
        prev_sess = __session_lookup(id);
        if (!prev_sess || prev_sess->state == SMB2_SESSION_EXPIRED)
                goto out;

        prev_user = prev_sess->user;
        if (!prev_user ||
            strcmp(user->name, prev_user->name) ||
            user->passkey_sz != prev_user->passkey_sz ||
            memcmp(user->passkey, prev_user->passkey, user->passkey_sz))
                goto out;

        ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_RECONNECT);
        err = ksmbd_conn_wait_idle_sess_id(conn, id);
        if (err) {
                ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);
                goto out;
        }

        ksmbd_destroy_file_table(&prev_sess->file_table);
        prev_sess->state = SMB2_SESSION_EXPIRED;
        ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);
        ksmbd_launch_ksmbd_durable_scavenger();
out:
        up_write(&conn->session_lock);
        up_write(&sessions_table_lock);
}

</document_content>
</document>
<document index="22">
<source>./kernel/fs/smb/server/mgmt/user_session.h</source>
<document_content>
struct ksmbd_session {
        u64                             id;

        __u16                           dialect;
        char                            ClientGUID[SMB2_CLIENT_GUID_SIZE];

        struct ksmbd_user               *user;
        unsigned int                    sequence_number;
        unsigned int                    flags;

        bool                            sign;
        bool                            enc;
        bool                            is_anonymous;

        int                             state;
        __u8                            *Preauth_HashValue;

        char                            sess_key[CIFS_KEY_SIZE];

        struct hlist_node               hlist;
        struct xarray                   ksmbd_chann_list;
        struct xarray                   tree_conns;
        struct ida                      tree_conn_ida;
        struct xarray                   rpc_handle_list;

        __u8                            smb3encryptionkey[SMB3_ENC_DEC_KEY_SIZE];
        __u8                            smb3decryptionkey[SMB3_ENC_DEC_KEY_SIZE];
        __u8                            smb3signingkey[SMB3_SIGN_KEY_SIZE];

        struct ksmbd_file_table         file_table;
        unsigned long                   last_active;
        rwlock_t                        tree_conns_lock;

        atomic_t                        refcnt;
};

static inline void set_session_flag(struct ksmbd_session *sess, int bit)
{
        sess->flags |= bit;
}

</document_content>
</document>
<document index="23">
<source>./kernel/fs/smb/common/smb2pdu.h</source>
<document_content>
struct smb2_sess_setup_req {
        struct smb2_hdr hdr;
        __le16 StructureSize; /* Must be 25 */
        __u8   Flags;
        __u8   SecurityMode;
        __le32 Capabilities;
        __le32 Channel;
        __le16 SecurityBufferOffset;
        __le16 SecurityBufferLength;
        __le64 PreviousSessionId;
        __u8   Buffer[];        /* variable length GSS security buffer */
} __packed;

struct smb2_sess_setup_rsp {
        struct smb2_hdr hdr;
        __le16 StructureSize; /* Must be 9 */
        __le16 SessionFlags;
        __le16 SecurityBufferOffset;
        __le16 SecurityBufferLength;
        __u8   Buffer[];        /* variable length GSS security buffer */
} __packed;

</document_content>
</document>
</documents>
