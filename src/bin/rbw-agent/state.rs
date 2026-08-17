use sha2::Digest as _;

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,
    pub master_password_reprompt: std::collections::HashSet<[u8; 32]>,
    pub master_password_reprompt_initialized: bool,
    // maps each protected cipherstring's hash to the id of the entry it
    // belongs to, so that a reprompt confirmation can be recorded against
    // the whole entry rather than just the one field that happened to
    // trigger it (see set_master_password_reprompt and the comment on
    // master_password_reprompt_confirmed below).
    pub master_password_reprompt_entry:
        std::collections::HashMap<[u8; 32], String>,
    // entry ids that have already been confirmed via a reprompt during the
    // current unlock. without this, every single decrypt of a protected
    // field reprompts independently, so a single `rbw get` on an entry with
    // more than one protected field (e.g. password + totp) shows multiple
    // prompts for what the user experiences as one access to one object.
    // tracking by entry id (rather than by individual field cipherstring)
    // means confirming any one protected field on an entry unlocks all of
    // that entry's other protected fields for the rest of this unlock.
    // cleared on lock, same as the unlocked keys themselves, so a
    // confirmation never outlives the unlock it was granted under.
    pub master_password_reprompt_confirmed: std::collections::HashSet<String>,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: rbw::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&self) {
        self.timeout.set(self.timeout_duration);
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.timeout.clear();
        self.master_password_reprompt_confirmed.clear();
    }

    // returns the entry id that the given protected cipherstring hash
    // belongs to, if any, for use as the key into
    // master_password_reprompt_confirmed.
    pub fn reprompt_entry_id(&self, hash: &[u8; 32]) -> Option<&str> {
        self.master_password_reprompt_entry
            .get(hash)
            .map(std::string::String::as_str)
    }

    pub fn set_sync_timeout(&self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }

    // the way we structure the client/agent split in rbw makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled, along with which entry each one belongs to. this
    // set is only updated when the agent itself does a sync, so it can't be
    // bypassed by editing the on-disk file directly. if the agent gets a
    // request for any of those cipherstrings that it saw marked as master
    // password reprompt during the most recent sync, it forces a reprompt -
    // unless that cipherstring's entry is already in
    // master_password_reprompt_confirmed, meaning the user has already
    // reproved possession of the master password for that entry earlier in
    // this same unlock. that second set is keyed by entry id rather than by
    // individual cipherstring, which is what keeps a single logical access
    // (e.g. `rbw get` on an entry with both a protected password and a
    // protected totp secret) from reprompting once per protected field
    // instead of once for the whole entry.
    pub fn set_master_password_reprompt(
        &mut self,
        entries: &[rbw::db::Entry],
    ) {
        self.master_password_reprompt.clear();
        self.master_password_reprompt_entry.clear();

        let mut hasher = sha2::Sha256::new();
        let mut insert = |entry_id: &str, s: Option<&str>| {
            if let Some(s) = s {
                if !s.is_empty() {
                    hasher.update(s);
                    let hash: [u8; 32] = hasher.finalize_reset().into();
                    self.master_password_reprompt.insert(hash);
                    self.master_password_reprompt_entry
                        .insert(hash, entry_id.to_string());
                }
            }
        };

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                rbw::db::EntryData::Login { password, totp, .. } => {
                    insert(&entry.id, password.as_deref());
                    insert(&entry.id, totp.as_deref());
                }
                rbw::db::EntryData::Card { number, code, .. } => {
                    insert(&entry.id, number.as_deref());
                    insert(&entry.id, code.as_deref());
                }
                rbw::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    insert(&entry.id, ssn.as_deref());
                    insert(&entry.id, passport_number.as_deref());
                }
                rbw::db::EntryData::SecureNote => {}
                rbw::db::EntryData::SshKey { private_key, .. } => {
                    insert(&entry.id, private_key.as_deref());
                }
            }

            for field in &entry.fields {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    insert(&entry.id, field.value.as_deref());
                }
            }
        }

        self.master_password_reprompt_initialized = true;
    }

    pub fn master_password_reprompt_initialized(&self) -> bool {
        self.master_password_reprompt_initialized
    }

    pub fn last_environment(&self) -> &rbw::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: rbw::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}
