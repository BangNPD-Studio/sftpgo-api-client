import type {
  OpenAPIClient,
  Parameters,
  UnknownParamsObject,
  OperationResponse,
  AxiosRequestConfig,
} from 'openapi-client-axios'; 

declare namespace Components {
    namespace Responses {
        export type BadRequest = Schemas.ApiResponse;
        export type Conflict = Schemas.ApiResponse;
        export type DefaultResponse = Schemas.ApiResponse;
        export type Forbidden = Schemas.ApiResponse;
        export type InternalServerError = Schemas.ApiResponse;
        export type NotFound = Schemas.ApiResponse;
        export type RequestEntityTooLarge = Schemas.ApiResponse;
        export type Unauthorized = Schemas.ApiResponse;
    }
    namespace Schemas {
        export interface APIKey {
            /**
             * unique key identifier
             */
            id?: string;
            /**
             * User friendly key name
             */
            name?: string;
            /**
             * We store the hash of the key. This is just like a password. For security reasons this field is omitted when you search/get API keys
             */
            key?: string; // password
            scope?: /**
             * Options:
             *   * `1` - admin scope. The API key will be used to impersonate an SFTPGo admin
             *   * `2` - user scope. The API key will be used to impersonate an SFTPGo user
             *
             */
            APIKeyScope;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            /**
             * last use time as unix timestamp in milliseconds. It is saved at most once every 10 minutes
             */
            last_use_at?: number; // int64
            /**
             * expiration time as unix timestamp in milliseconds
             */
            expires_at?: number; // int64
            /**
             * optional description
             */
            description?: string;
            /**
             * username associated with this API key. If empty and the scope is "user scope" the key can impersonate any user
             */
            user?: string;
            /**
             * admin associated with this API key. If empty and the scope is "admin scope" the key can impersonate any admin
             */
            admin?: string;
        }
        /**
         * Options:
         *   * `1` - admin scope. The API key will be used to impersonate an SFTPGo admin
         *   * `2` - user scope. The API key will be used to impersonate an SFTPGo user
         *
         */
        export type APIKeyScope = 1 | 2;
        export interface Admin {
            id?: number; // int32
            /**
             * status:
             *   * `0` user is disabled, login is not allowed
             *   * `1` user is enabled
             *
             */
            status?: 0 | 1;
            /**
             * username is unique
             */
            username?: string;
            /**
             * optional description, for example the admin full name
             */
            description?: string;
            /**
             * Admin password. For security reasons this field is omitted when you search/get admins
             */
            password?: string; // password
            email?: string; // email
            permissions?: /**
             * Admin permissions:
             *   * `*` - all permissions are granted
             *   * `add_users` - add new users is allowed
             *   * `edit_users` - change existing users is allowed
             *   * `del_users` - remove users is allowed
             *   * `view_users` - list users is allowed
             *   * `view_conns` - list active connections is allowed
             *   * `close_conns` - close active connections is allowed
             *   * `view_status` - view the server status is allowed
             *   * `manage_admins` - manage other admins is allowed
             *   * `manage_folders` - manage folders is allowed
             *   * `manage_groups` - manage groups is allowed
             *   * `manage_apikeys` - manage API keys is allowed
             *   * `quota_scans` - view and start quota scans is allowed
             *   * `manage_system` - backups and restores are allowed
             *   * `manage_defender` - remove ip from the dynamic blocklist is allowed
             *   * `view_defender` - list the dynamic blocklist is allowed
             *   * `retention_checks` - view and start retention checks is allowed
             *   * `metadata_checks` - view and start metadata checks is allowed
             *   * `view_events` - view and search filesystem and provider events is allowed
             *   * `manage_event_rules` - manage event actions and rules is allowed
             *   * `manage_roles` - manage roles is allowed
             *   * `manage_ip_lists` - manage global and ratelimter allow lists and defender block and safe lists is allowed
             *
             */
            AdminPermissions[];
            filters?: AdminFilters;
            /**
             * Free form text field
             */
            additional_info?: string;
            /**
             * Groups automatically selected for new users created by this admin. The admin will still be able to choose different groups. These settings are only used for this admin UI and they will be ignored in REST API/hooks.
             */
            groups?: AdminGroupMapping[];
            /**
             * creation time as unix timestamp in milliseconds. It will be 0 for admins created before v2.2.0
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            /**
             * Last user login as unix timestamp in milliseconds. It is saved at most once every 10 minutes
             */
            last_login?: number; // int64
            /**
             * If set the admin can only administer users with the same role. Role admins cannot have the following permissions: "manage_admins", "manage_apikeys", "manage_system", "manage_event_rules", "manage_roles", "manage_ip_lists"
             */
            role?: string;
        }
        export interface AdminFilters {
            /**
             * only clients connecting from these IP/Mask are allowed. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32"
             * example:
             * [
             *   "192.0.2.0/24",
             *   "2001:db8::/32"
             * ]
             */
            allow_list?: string[];
            /**
             * API key auth allows to impersonate this administrator with an API key
             */
            allow_api_key_auth?: boolean;
            totp_config?: AdminTOTPConfig;
            recovery_codes?: /* Recovery codes to use if the user loses access to their second factor auth device. Each code can only be used once, you should use these codes to login and disable or reset 2FA for your account */ RecoveryCode[];
            preferences?: AdminPreferences;
        }
        export interface AdminGroupMapping {
            /**
             * group name
             */
            name?: string;
            options?: AdminGroupMappingOptions;
        }
        export interface AdminGroupMappingOptions {
            /**
             * Add to new users as:
             *   * `0` - the admin's group will be added as membership group for new users
             *   * `1` - the admin's group will be added as primary group for new users
             *   * `2` - the admin's group will be added as secondary group for new users
             *
             */
            add_to_users_as?: 0 | 1 | 2;
        }
        /**
         * Admin permissions:
         *   * `*` - all permissions are granted
         *   * `add_users` - add new users is allowed
         *   * `edit_users` - change existing users is allowed
         *   * `del_users` - remove users is allowed
         *   * `view_users` - list users is allowed
         *   * `view_conns` - list active connections is allowed
         *   * `close_conns` - close active connections is allowed
         *   * `view_status` - view the server status is allowed
         *   * `manage_admins` - manage other admins is allowed
         *   * `manage_folders` - manage folders is allowed
         *   * `manage_groups` - manage groups is allowed
         *   * `manage_apikeys` - manage API keys is allowed
         *   * `quota_scans` - view and start quota scans is allowed
         *   * `manage_system` - backups and restores are allowed
         *   * `manage_defender` - remove ip from the dynamic blocklist is allowed
         *   * `view_defender` - list the dynamic blocklist is allowed
         *   * `retention_checks` - view and start retention checks is allowed
         *   * `metadata_checks` - view and start metadata checks is allowed
         *   * `view_events` - view and search filesystem and provider events is allowed
         *   * `manage_event_rules` - manage event actions and rules is allowed
         *   * `manage_roles` - manage roles is allowed
         *   * `manage_ip_lists` - manage global and ratelimter allow lists and defender block and safe lists is allowed
         *
         */
        export type AdminPermissions = "*" | "add_users" | "edit_users" | "del_users" | "view_users" | "view_conns" | "close_conns" | "view_status" | "manage_admins" | "manage_folders" | "manage_groups" | "manage_apikeys" | "quota_scans" | "manage_system" | "manage_defender" | "view_defender" | "retention_checks" | "metadata_checks" | "view_events" | "manage_event_rules" | "manage_roles" | "manage_ip_lists";
        export interface AdminPreferences {
            /**
             * Allow to hide some sections from the user page. These are not security settings and are not enforced server side in any way. They are only intended to simplify the user page in the WebAdmin UI. 1 means hide groups section, 2 means hide filesystem section, "users_base_dir" must be set in the config file otherwise this setting is ignored, 4 means hide virtual folders section, 8 means hide profile section, 16 means hide ACLs section, 32 means hide disk and bandwidth quota limits section, 64 means hide advanced settings section. The settings can be combined
             */
            hide_user_page_sections?: number;
            /**
             * Defines the default expiration for newly created users as number of days. 0 means no expiration
             */
            default_users_expiration?: number;
        }
        export interface AdminProfile {
            email?: string; // email
            description?: string;
            /**
             * If enabled, you can impersonate this admin, in REST API, using an API key. If disabled admin credentials are required for impersonation
             */
            allow_api_key_auth?: boolean;
        }
        export interface AdminTOTPConfig {
            enabled?: boolean;
            /**
             * This name must be defined within the "totp" section of the SFTPGo configuration file. You will be unable to save a user/admin referencing a missing config_name
             */
            config_name?: string;
            secret?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
        }
        export interface ApiResponse {
            /**
             * message, can be empty
             */
            message?: string;
            /**
             * error description if any
             */
            error?: string;
        }
        /**
         * Azure Blob Storage configuration details
         */
        export interface AzureBlobFsConfig {
            container?: string;
            /**
             * Storage Account Name, leave blank to use SAS URL
             */
            account_name?: string;
            account_key?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            sas_url?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * optional endpoint. Default is "blob.core.windows.net". If you use the emulator the endpoint must include the protocol, for example "http://127.0.0.1:10000"
             */
            endpoint?: string;
            /**
             * the buffer size (in MB) to use for multipart uploads. If this value is set to zero, the default value (5MB) will be used.
             */
            upload_part_size?: number;
            /**
             * the number of parts to upload in parallel. If this value is set to zero, the default value (5) will be used
             */
            upload_concurrency?: number;
            /**
             * the buffer size (in MB) to use for multipart downloads. If this value is set to zero, the default value (5MB) will be used.
             */
            download_part_size?: number;
            /**
             * the number of parts to download in parallel. If this value is set to zero, the default value (5) will be used
             */
            download_concurrency?: number;
            access_tier?: "" | "Archive" | "Hot" | "Cool";
            /**
             * key_prefix is similar to a chroot directory for a local filesystem. If specified the user will only see contents that starts with this prefix and so you can restrict access to a specific virtual folder. The prefix, if not empty, must not start with "/" and must end with "/". If empty the whole container contents will be available
             * example:
             * folder/subfolder/
             */
            key_prefix?: string;
            use_emulator?: boolean;
        }
        export interface BackupData {
            users?: User[];
            folders?: /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ BaseVirtualFolder[];
            groups?: Group[];
            admins?: Admin[];
            api_keys?: APIKey[];
            shares?: Share[];
            event_actions?: EventAction[];
            event_rules?: EventRule[];
            roles?: Role[];
            version?: number;
        }
        export interface BandwidthLimit {
            /**
             * Source networks in CIDR notation as defined in RFC 4632 and RFC 4291 for example `192.0.2.0/24` or `2001:db8::/32`. The limit applies if the defined networks contain the client IP
             */
            sources?: string[];
            /**
             * Maximum upload bandwidth as KB/s, 0 means unlimited
             */
            upload_bandwidth?: number; // int32
            /**
             * Maximum download bandwidth as KB/s, 0 means unlimited
             */
            download_bandwidth?: number; // int32
        }
        export interface BaseEventAction {
            id?: number; // int32
            /**
             * unique name
             */
            name?: string;
            /**
             * optional description
             */
            description?: string;
            type?: /**
             * Supported event action types:
             *   * `1` - HTTP
             *   * `2` - Command
             *   * `3` - Email
             *   * `4` - Backup
             *   * `5` - User quota reset
             *   * `6` - Folder quota reset
             *   * `7` - Transfer quota reset
             *   * `8` - Data retention check
             *   * `9` - Filesystem
             *   * `10` - Metadata check
             *   * `11` - Password expiration check
             *   * `12` - User expiration check
             *   * `13` - Identity Provider account check
             *
             */
            EventActionTypes;
            options?: BaseEventActionOptions;
            /**
             * list of event rules names associated with this action
             */
            rules?: string[];
        }
        export interface BaseEventActionOptions {
            http_config?: EventActionHTTPConfig;
            cmd_config?: EventActionCommandConfig;
            email_config?: EventActionEmailConfig;
            retention_config?: EventActionDataRetentionConfig;
            fs_config?: EventActionFilesystemConfig;
            pwd_expiration_config?: EventActionPasswordExpiration;
            idp_config?: EventActionIDPAccountCheck;
        }
        export interface BaseEventRule {
            id?: number; // int32
            /**
             * unique name
             */
            name?: string;
            /**
             * status:
             *   * `0` disabled
             *   * `1` enabled
             *
             */
            status?: 0 | 1;
            /**
             * optional description
             */
            description?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in millisecond
             */
            updated_at?: number; // int64
            trigger?: /**
             * Supported event trigger types:
             *   * `1` - Filesystem event
             *   * `2` - Provider event
             *   * `3` - Schedule
             *   * `4` - IP blocked
             *   * `5` - Certificate renewal
             *   * `6` - On demand, like schedule but executed on demand
             *   * `7` - Identity provider login
             *
             */
            EventTriggerTypes;
            conditions?: EventConditions;
        }
        export interface BaseTOTPConfig {
            enabled?: boolean;
            /**
             * This name must be defined within the "totp" section of the SFTPGo configuration file. You will be unable to save a user/admin referencing a missing config_name
             */
            config_name?: string;
            secret?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
        }
        /**
         * Additional user options
         */
        export interface BaseUserFilters {
            /**
             * only clients connecting from these IP/Mask are allowed. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32"
             * example:
             * [
             *   "192.0.2.0/24",
             *   "2001:db8::/32"
             * ]
             */
            allowed_ip?: string[];
            /**
             * clients connecting from these IP/Mask are not allowed. Denied rules are evaluated before allowed ones
             * example:
             * [
             *   "172.16.0.0/16"
             * ]
             */
            denied_ip?: string[];
            /**
             * if null or empty any available login method is allowed
             */
            denied_login_methods?: /**
             * Available login methods. To enable multi-step authentication you have to allow only multi-step login methods
             *   * `publickey`
             *   * `password`, password for all the supported protocols
             *   * `password-over-SSH`, password over SSH protocol (SSH/SFTP/SCP)
             *   * `keyboard-interactive`
             *   * `publickey+password` - multi-step auth: public key and password
             *   * `publickey+keyboard-interactive` - multi-step auth: public key and keyboard interactive
             *   * `TLSCertificate`
             *   * `TLSCertificate+password` - multi-step auth: TLS client certificate and password
             *
             */
            LoginMethods[];
            /**
             * if null or empty any available protocol is allowed
             */
            denied_protocols?: /**
             * Protocols:
             *   * `SSH` - includes both SFTP and SSH commands
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV over HTTP/HTTPS
             *   * `HTTP` - WebClient/REST API
             *
             */
            SupportedProtocols[];
            /**
             * filters based on shell like file patterns. These restrictions do not apply to files listing for performance reasons, so a denied file cannot be downloaded/overwritten/renamed but it will still be in the list of files. Please note that these restrictions can be easily bypassed
             */
            file_patterns?: PatternsFilter[];
            /**
             * maximum allowed size, as bytes, for a single file upload. The upload will be aborted if/when the size of the file being sent exceeds this limit. 0 means unlimited. This restriction does not apply for SSH system commands such as `git` and `rsync`
             */
            max_upload_file_size?: number; // int64
            /**
             * defines the TLS certificate field to use as username. For FTP clients it must match the name provided using the "USER" command. For WebDAV, if no username is provided, the CN will be used as username. For WebDAV clients it must match the implicit or provided username. Ignored if mutual TLS is disabled. Currently the only supported value is `CommonName`
             */
            tls_username?: string;
            hooks?: /* User specific hook overrides */ HooksFilter;
            /**
             * Disable checks for existence and automatic creation of home directory and virtual folders. SFTPGo requires that the user's home directory, virtual folder root, and intermediate paths to virtual folders exist to work properly. If you already know that the required directories exist, disabling these checks will speed up login. You could, for example, disable these checks after the first login
             * example:
             * false
             */
            disable_fs_checks?: boolean;
            /**
             * WebClient/user REST API related configuration options
             */
            web_client?: /**
             * Options:
             *   * `publickey-change-disabled` - changing SSH public keys is not allowed
             *   * `write-disabled` - upload, rename, delete are not allowed even if the user has permissions for these actions
             *   * `mfa-disabled` - enabling multi-factor authentication is not allowed. This option cannot be set if the user has MFA already enabled
             *   * `password-change-disabled` - changing password is not allowed
             *   * `api-key-auth-change-disabled` - enabling/disabling API key authentication is not allowed
             *   * `info-change-disabled` - changing info such as email and description is not allowed
             *   * `shares-disabled` - sharing files and directories with external users is not allowed
             *   * `password-reset-disabled` - resetting the password is not allowed
             *   * `shares-without-password-disabled` - creating shares without password protection is not allowed
             *
             */
            WebClientOptions[];
            /**
             * API key authentication allows to impersonate this user with an API key
             */
            allow_api_key_auth?: boolean;
            user_type?: /* This is an hint for authentication plugins. It is ignored when using SFTPGo internal authentication */ UserType;
            bandwidth_limits?: BandwidthLimit[];
            /**
             * Defines the cache time, in seconds, for users authenticated using an external auth hook. 0 means no cache
             */
            external_auth_cache_time?: number;
            /**
             * Specifies an alternate starting directory. If not set, the default is "/". This option is supported for SFTP/SCP, FTP and HTTP (WebClient/REST API) protocols. Relative paths will use this directory as base.
             */
            start_directory?: string;
            /**
             * Defines protocols that require two factor authentication
             */
            two_factor_protocols?: /**
             * Protocols:
             *   * `SSH` - includes both SFTP and SSH commands
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `HTTP` - WebClient/REST API
             *
             */
            MFAProtocols[];
            /**
             * Set to `1` to require TLS for both data and control connection. his setting is useful if you want to allow both encrypted and plain text FTP sessions globally and then you want to require encrypted sessions on a per-user basis. It has no effect if TLS is already required for all users in the configuration file.
             */
            ftp_security?: 0 | 1;
            /**
             * If enabled the user can login with any password or no password at all. Anonymous users are supported for FTP and WebDAV protocols and permissions will be automatically set to "list" and "download" (read only)
             */
            is_anonymous?: boolean;
            /**
             * Defines the default expiration for newly created shares as number of days. 0 means no expiration
             */
            default_shares_expiration?: number;
            /**
             * Defines the maximum allowed expiration, as a number of days, when a user creates or updates a share. 0 means no expiration
             */
            max_shares_expiration?: number;
            /**
             * The password expires after the defined number of days. 0 means no expiration
             */
            password_expiration?: number;
        }
        /**
         * Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path.
         */
        export interface BaseVirtualFolder {
            id?: number; // int32
            /**
             * unique name for this virtual folder
             */
            name?: string;
            /**
             * absolute filesystem path to use as virtual folder
             */
            mapped_path?: string;
            /**
             * optional description
             */
            description?: string;
            used_quota_size?: number; // int64
            used_quota_files?: number; // int32
            /**
             * Last quota update as unix timestamp in milliseconds
             */
            last_quota_update?: number; // int64
            /**
             * list of usernames associated with this virtual folder
             */
            users?: string[];
            filesystem?: /* Storage filesystem details */ FilesystemConfig;
        }
        export interface ConditionOptions {
            names?: ConditionPattern[];
            group_names?: ConditionPattern[];
            role_names?: ConditionPattern[];
            fs_paths?: ConditionPattern[];
            protocols?: ("SFTP" | "SCP" | "SSH" | "FTP" | "DAV" | "HTTP" | "HTTPShare" | "OIDC")[];
            provider_objects?: ("user" | "group" | "admin" | "api_key" | "share" | "event_action" | "event_rule")[];
            min_size?: number; // int64
            max_size?: number; // int64
            /**
             * allow concurrent execution from multiple nodes
             */
            concurrent_execution?: boolean;
        }
        export interface ConditionPattern {
            pattern?: string;
            inverse_match?: boolean;
        }
        export interface ConnectionStatus {
            /**
             * connected username
             */
            username?: string;
            /**
             * unique connection identifier
             */
            connection_id?: string;
            /**
             * client version
             */
            client_version?: string;
            /**
             * Remote address for the connected client
             */
            remote_address?: string;
            /**
             * connection time as unix timestamp in milliseconds
             */
            connection_time?: number; // int64
            /**
             * Last SSH/FTP command or WebDAV method
             */
            command?: string;
            /**
             * last client activity as unix timestamp in milliseconds
             */
            last_activity?: number; // int64
            protocol?: "SFTP" | "SCP" | "SSH" | "FTP" | "DAV";
            active_transfers?: Transfer[];
            /**
             * Node identifier, omitted for single node installations
             */
            node?: string;
        }
        /**
         * Crypt filesystem configuration details
         */
        export interface CryptFsConfig {
            passphrase?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * The read buffer size, as MB, to use for downloads. 0 means no buffering, that's fine in most use cases.
             */
            read_buffer_size?: number;
            /**
             * The write buffer size, as MB, to use for uploads. 0 means no buffering, that's fine in most use cases.
             */
            write_buffer_size?: number;
        }
        export interface DataProviderStatus {
            is_active?: boolean;
            driver?: string;
            error?: string;
        }
        export interface DefenderEntry {
            id?: string;
            ip?: string;
            /**
             * the score increases whenever a violation is detected, such as an attempt to log in using an incorrect password or invalid username. If the score exceeds the configured threshold, the IP is banned. Omitted for banned IPs
             */
            score?: number;
            /**
             * date time until the IP is banned. For already banned hosts, the ban time is increased each time a new violation is detected. Omitted if the IP is not banned
             */
            ban_time?: string; // date-time
        }
        export interface DirEntry {
            /**
             * name of the file (or subdirectory) described by the entry. This name is the final element of the path (the base name), not the entire path
             */
            name?: string;
            /**
             * file size, omitted for folders and non regular files
             */
            size?: number; // int64
            /**
             * File mode and permission bits. More details here: https://golang.org/pkg/io/fs/#FileMode.
             * Let's see some examples:
             * - for a directory mode&2147483648 != 0
             * - for a symlink mode&134217728 != 0
             * - for a regular file mode&2401763328 == 0
             *
             */
            mode?: number;
            last_modified?: string; // date-time
        }
        export type DumpDataScopes = "users" | "folders" | "groups" | "admins" | "api_keys" | "shares" | "actions" | "rules" | "roles" | "ip_lists" | "configs";
        export interface EventAction {
            id?: number; // int32
            /**
             * unique name
             */
            name?: string;
            /**
             * optional description
             */
            description?: string;
            type?: /**
             * Supported event action types:
             *   * `1` - HTTP
             *   * `2` - Command
             *   * `3` - Email
             *   * `4` - Backup
             *   * `5` - User quota reset
             *   * `6` - Folder quota reset
             *   * `7` - Transfer quota reset
             *   * `8` - Data retention check
             *   * `9` - Filesystem
             *   * `10` - Metadata check
             *   * `11` - Password expiration check
             *   * `12` - User expiration check
             *   * `13` - Identity Provider account check
             *
             */
            EventActionTypes;
            options?: BaseEventActionOptions;
            /**
             * list of event rules names associated with this action
             */
            rules?: string[];
            /**
             * execution order
             */
            order?: number;
            relation_options?: EventActionOptions;
        }
        export interface EventActionCommandConfig {
            /**
             * absolute path to the command to execute
             */
            cmd?: string;
            /**
             * command line arguments
             */
            args?: string[];
            timeout?: number;
            env_vars?: KeyValue[];
        }
        export interface EventActionDataRetentionConfig {
            folders?: FolderRetention[];
        }
        export interface EventActionEmailConfig {
            recipients?: string[];
            bcc?: string[];
            subject?: string;
            body?: string;
            /**
             * Content type:
             *   * `0` text/plain
             *   * `1` text/html
             *
             */
            content_type?: 0 | 1;
            /**
             * list of file paths to attach. The total size is limited to 10 MB
             */
            attachments?: string[];
        }
        export interface EventActionFilesystemConfig {
            type?: /**
             * Supported filesystem action types:
             *   * `1` - Rename
             *   * `2` - Delete
             *   * `3` - Mkdis
             *   * `4` - Exist
             *   * `5` - Compress
             *   * `6` - Copy
             *
             */
            FilesystemActionTypes;
            renames?: KeyValue[];
            mkdirs?: string[];
            deletes?: string[];
            exist?: string[];
            copy?: KeyValue[];
            compress?: EventActionFsCompress;
        }
        export interface EventActionFsCompress {
            /**
             * Full path to the (zip) archive to create. The parent dir must exist
             */
            name?: string;
            /**
             * paths to add the archive
             */
            paths?: string[];
        }
        export interface EventActionHTTPConfig {
            /**
             * HTTP endpoint
             * example:
             * https://example.com
             */
            endpoint?: string;
            username?: string;
            password?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * headers to add
             */
            headers?: KeyValue[];
            /**
             * Ignored for multipart requests with files as attachments
             */
            timeout?: number;
            /**
             * if enabled the HTTP client accepts any TLS certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.
             */
            skip_tls_verify?: boolean;
            method?: "GET" | "POST" | "PUT" | "DELETE";
            query_parameters?: KeyValue[];
            /**
             * HTTP POST/PUT body
             */
            body?: string;
            /**
             * Multipart requests allow to combine one or more sets of data into a single body. For each part, you can set a file path or a body as text. Placeholders are supported in file path, body, header values.
             */
            parts?: HTTPPart[];
        }
        export interface EventActionIDPAccountCheck {
            /**
             * Account check mode:
             *   * `0` Create or update the account
             *   * `1` Create the account if it doesn't exist
             *
             */
            mode?: 0 | 1;
            /**
             * SFTPGo user template in JSON format
             */
            template_user?: string;
            /**
             * SFTPGo admin template in JSON format
             */
            template_admin?: string;
        }
        export interface EventActionMinimal {
            name?: string;
            /**
             * execution order
             */
            order?: number;
            relation_options?: EventActionOptions;
        }
        export interface EventActionOptions {
            is_failure_action?: boolean;
            stop_on_failure?: boolean;
            execute_sync?: boolean;
        }
        export interface EventActionPasswordExpiration {
            /**
             * An email notification will be generated for users whose password expires in a number of days less than or equal to this threshold
             */
            threshold?: number;
        }
        /**
         * Supported event action types:
         *   * `1` - HTTP
         *   * `2` - Command
         *   * `3` - Email
         *   * `4` - Backup
         *   * `5` - User quota reset
         *   * `6` - Folder quota reset
         *   * `7` - Transfer quota reset
         *   * `8` - Data retention check
         *   * `9` - Filesystem
         *   * `10` - Metadata check
         *   * `11` - Password expiration check
         *   * `12` - User expiration check
         *   * `13` - Identity Provider account check
         *
         */
        export type EventActionTypes = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13;
        export interface EventConditions {
            fs_events?: ("upload" | "download" | "delete" | "rename" | "mkdir" | "rmdir" | "copy" | "ssh_cmd" | "pre-upload" | "pre-download" | "pre-delete" | "first-upload" | "first-download")[];
            provider_events?: ("add" | "update" | "delete")[];
            schedules?: Schedule[];
            /**
             * IDP login events:
             *   - `0` any login event
             *   - `1` user login event
             *   - `2` admin login event
             *
             */
            idp_login_event?: 0 | 1 | 2;
            options?: ConditionOptions;
        }
        /**
         * Protocols:
         *   * `SSH` - SSH commands
         *   * `SFTP` - SFTP protocol
         *   * `SCP` - SCP protocol
         *   * `FTP` - plain FTP and FTPES/FTPS
         *   * `DAV` - WebDAV
         *   * `HTTP` - WebClient/REST API
         *   * `HTTPShare` - the event is generated in a public share
         *   * `DataRetention` - the event is generated by a data retention check
         *   * `EventAction` - the event is generated by an EventManager action
         *   * `OIDC` - OpenID Connect
         *
         */
        export type EventProtocols = "SSH" | "SFTP" | "SCP" | "FTP" | "DAV" | "HTTP" | "HTTPShare" | "DataRetention" | "EventAction" | "OIDC";
        export interface EventRule {
            id?: number; // int32
            /**
             * unique name
             */
            name?: string;
            /**
             * status:
             *   * `0` disabled
             *   * `1` enabled
             *
             */
            status?: 0 | 1;
            /**
             * optional description
             */
            description?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in millisecond
             */
            updated_at?: number; // int64
            trigger?: /**
             * Supported event trigger types:
             *   * `1` - Filesystem event
             *   * `2` - Provider event
             *   * `3` - Schedule
             *   * `4` - IP blocked
             *   * `5` - Certificate renewal
             *   * `6` - On demand, like schedule but executed on demand
             *   * `7` - Identity provider login
             *
             */
            EventTriggerTypes;
            conditions?: EventConditions;
            actions?: EventAction[];
        }
        export interface EventRuleMinimal {
            id?: number; // int32
            /**
             * unique name
             */
            name?: string;
            /**
             * status:
             *   * `0` disabled
             *   * `1` enabled
             *
             */
            status?: 0 | 1;
            /**
             * optional description
             */
            description?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in millisecond
             */
            updated_at?: number; // int64
            trigger?: /**
             * Supported event trigger types:
             *   * `1` - Filesystem event
             *   * `2` - Provider event
             *   * `3` - Schedule
             *   * `4` - IP blocked
             *   * `5` - Certificate renewal
             *   * `6` - On demand, like schedule but executed on demand
             *   * `7` - Identity provider login
             *
             */
            EventTriggerTypes;
            conditions?: EventConditions;
            actions?: EventActionMinimal[];
        }
        /**
         * Supported event trigger types:
         *   * `1` - Filesystem event
         *   * `2` - Provider event
         *   * `3` - Schedule
         *   * `4` - IP blocked
         *   * `5` - Certificate renewal
         *   * `6` - On demand, like schedule but executed on demand
         *   * `7` - Identity provider login
         *
         */
        export type EventTriggerTypes = 1 | 2 | 3 | 4 | 5 | 6 | 7;
        export interface FTPDBinding {
            /**
             * TCP address the server listen on
             */
            address?: string;
            /**
             * the port used for serving requests
             */
            port?: number;
            /**
             * apply the proxy configuration, if any
             */
            apply_proxy_config?: boolean;
            /**
             * TLS mode:
             *   * `0` - clear or explicit TLS
             *   * `1` - explicit TLS required
             *   * `2` - implicit TLS
             *
             */
            tls_mode?: 0 | 1 | 2;
            min_tls_version?: /**
             * TLS version:
             *   * `12` - TLS 1.2
             *   * `13` - TLS 1.3
             *
             */
            TLSVersions;
            /**
             * External IP address for passive connections
             */
            force_passive_ip?: string;
            passive_ip_overrides?: PassiveIPOverride[];
            /**
             * 1 means that client certificate authentication is required in addition to FTP authentication
             */
            client_auth_type?: number;
            /**
             * List of supported cipher suites for TLS version 1.2. If empty  a default list of secure cipher suites is used, with a preference order based on hardware performance
             */
            tls_cipher_suites?: string[];
            /**
             * Active connections security:
             *   * `0` - require matching peer IP addresses of control and data connection
             *   * `1` - disable any checks
             *
             */
            passive_connections_security?: 0 | 1;
            /**
             * Active connections security:
             *   * `0` - require matching peer IP addresses of control and data connection
             *   * `1` - disable any checks
             *
             */
            active_connections_security?: 0 | 1;
            /**
             * If enabled any FTP command will be logged
             */
            debug?: boolean;
        }
        export interface FTPPassivePortRange {
            start?: number;
            end?: number;
        }
        export interface FTPServiceStatus {
            is_active?: boolean;
            bindings?: FTPDBinding[] | null;
            passive_port_range?: FTPPassivePortRange;
        }
        /**
         * Supported filesystem action types:
         *   * `1` - Rename
         *   * `2` - Delete
         *   * `3` - Mkdis
         *   * `4` - Exist
         *   * `5` - Compress
         *   * `6` - Copy
         *
         */
        export type FilesystemActionTypes = 1 | 2 | 3 | 4 | 5 | 6;
        /**
         * Storage filesystem details
         */
        export interface FilesystemConfig {
            provider?: /**
             * Filesystem providers:
             *   * `0` - Local filesystem
             *   * `1` - S3 Compatible Object Storage
             *   * `2` - Google Cloud Storage
             *   * `3` - Azure Blob Storage
             *   * `4` - Local filesystem encrypted
             *   * `5` - SFTP
             *   * `6` - HTTP filesystem
             *
             */
            FsProviders;
            osconfig?: OSFsConfig;
            s3config?: /* S3 Compatible Object Storage configuration details */ S3Config;
            gcsconfig?: /* Google Cloud Storage configuration details. The "credentials" field must be populated only when adding/updating a user. It will be always omitted, since there are sensitive data, when you search/get users */ GCSConfig;
            azblobconfig?: /* Azure Blob Storage configuration details */ AzureBlobFsConfig;
            cryptconfig?: /* Crypt filesystem configuration details */ CryptFsConfig;
            sftpconfig?: SFTPFsConfig;
            httpconfig?: HTTPFsConfig;
        }
        export interface FolderQuotaScan {
            /**
             * folder name to which the quota scan refers
             */
            name?: string;
            /**
             * scan start time as unix timestamp in milliseconds
             */
            start_time?: number; // int64
        }
        export interface FolderRetention {
            /**
             * virtual directory path as seen by users, if no other specific retention is defined, the retention applies for sub directories too. For example if retention is defined for the paths "/" and "/sub" then the retention for "/" is applied for any file outside the "/sub" directory
             * example:
             * /
             */
            path?: string;
            /**
             * retention time in hours. All the files with a modification time older than the defined value will be deleted. 0 means exclude this path
             * example:
             * 24
             */
            retention?: number;
            /**
             * if enabled, empty directories will be deleted
             */
            delete_empty_dirs?: boolean;
            /**
             * if enabled, files will be deleted even if the user does not have the delete permission. The default is "false" which means that files will be skipped if the user does not have permission to delete them. File patterns filters will always be silently ignored
             */
            ignore_user_permissions?: boolean;
        }
        export interface FsEvent {
            id?: string;
            /**
             * unix timestamp in nanoseconds
             */
            timestamp?: number; // int64
            action?: FsEventAction;
            username?: string;
            fs_path?: string;
            fs_target_path?: string;
            virtual_path?: string;
            virtual_target_path?: string;
            ssh_cmd?: string;
            file_size?: number; // int64
            /**
             * elapsed time as milliseconds
             */
            elapsed?: number; // int64
            status?: /**
             * Event status:
             *   * `1` - no error
             *   * `2` - generic error
             *   * `3` - quota exceeded error
             *
             */
            FsEventStatus;
            protocol?: /**
             * Protocols:
             *   * `SSH` - SSH commands
             *   * `SFTP` - SFTP protocol
             *   * `SCP` - SCP protocol
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV
             *   * `HTTP` - WebClient/REST API
             *   * `HTTPShare` - the event is generated in a public share
             *   * `DataRetention` - the event is generated by a data retention check
             *   * `EventAction` - the event is generated by an EventManager action
             *   * `OIDC` - OpenID Connect
             *
             */
            EventProtocols;
            ip?: string;
            session_id?: string;
            fs_provider?: /**
             * Filesystem providers:
             *   * `0` - Local filesystem
             *   * `1` - S3 Compatible Object Storage
             *   * `2` - Google Cloud Storage
             *   * `3` - Azure Blob Storage
             *   * `4` - Local filesystem encrypted
             *   * `5` - SFTP
             *   * `6` - HTTP filesystem
             *
             */
            FsProviders;
            bucket?: string;
            endpoint?: string;
            open_flags?: string;
            role?: string;
            instance_id?: string;
        }
        export type FsEventAction = "download" | "upload" | "first-upload" | "first-download" | "delete" | "rename" | "mkdir" | "rmdir" | "ssh_cmd";
        /**
         * Event status:
         *   * `1` - no error
         *   * `2` - generic error
         *   * `3` - quota exceeded error
         *
         */
        export type FsEventStatus = 1 | 2 | 3;
        /**
         * Filesystem providers:
         *   * `0` - Local filesystem
         *   * `1` - S3 Compatible Object Storage
         *   * `2` - Google Cloud Storage
         *   * `3` - Azure Blob Storage
         *   * `4` - Local filesystem encrypted
         *   * `5` - SFTP
         *   * `6` - HTTP filesystem
         *
         */
        export type FsProviders = 0 | 1 | 2 | 3 | 4 | 5 | 6;
        /**
         * Google Cloud Storage configuration details. The "credentials" field must be populated only when adding/updating a user. It will be always omitted, since there are sensitive data, when you search/get users
         */
        export interface GCSConfig {
            bucket?: string;
            credentials?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * Automatic credentials:
             *   * `0` - disabled, explicit credentials, using a JSON credentials file, must be provided. This is the default value if the field is null
             *   * `1` - enabled, we try to use the Application Default Credentials (ADC) strategy to find your application's credentials
             *
             */
            automatic_credentials?: 0 | 1;
            storage_class?: string;
            /**
             * The ACL to apply to uploaded objects. Leave empty to use the default ACL. For more information and available ACLs, refer to the JSON API here: https://cloud.google.com/storage/docs/access-control/lists#predefined-acl
             */
            acl?: string;
            /**
             * key_prefix is similar to a chroot directory for a local filesystem. If specified the user will only see contents that starts with this prefix and so you can restrict access to a specific virtual folder. The prefix, if not empty, must not start with "/" and must end with "/". If empty the whole bucket contents will be available
             * example:
             * folder/subfolder/
             */
            key_prefix?: string;
            /**
             * The buffer size (in MB) to use for multipart uploads. The default value is 16MB. 0 means use the default
             */
            upload_part_size?: number;
            /**
             * The maximum time allowed, in seconds, to upload a single chunk. The default value is 32. 0 means use the default
             */
            upload_part_max_time?: number;
        }
        export interface Group {
            id?: number; // int32
            /**
             * name is unique
             */
            name?: string;
            /**
             * optional description
             */
            description?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            user_settings?: GroupUserSettings;
            /**
             * mapping between virtual SFTPGo paths and folders
             */
            virtual_folders?: /* A virtual folder is a mapping between a SFTPGo virtual path and a filesystem path outside the user home directory. The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory. The parent directory for the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login. */ VirtualFolder[];
            /**
             * list of usernames associated with this group
             */
            users?: string[];
            /**
             * list of admins usernames associated with this group
             */
            admins?: string[];
        }
        export interface GroupMapping {
            /**
             * group name
             */
            name?: string;
            /**
             * Group type:
             *   * `1` - Primary group
             *   * `2` - Secondary group
             *   * `3` - Membership only, no settings are inherited from this group type
             *
             */
            type?: 1 | 2 | 3;
        }
        export interface GroupUserSettings {
            home_dir?: string;
            max_sessions?: number; // int32
            quota_size?: number; // int64
            quota_files?: number; // int32
            /**
             * hash map with directory as key and an array of permissions as value. Directories must be absolute paths, permissions for root directory ("/") are required
             * example:
             * {
             *   "/": [
             *     "*"
             *   ],
             *   "/somedir": [
             *     "list",
             *     "download"
             *   ]
             * }
             */
            permissions?: {
                [name: string]: [
                    /**
                     * Permissions:
                     *   * `*` - all permissions are granted
                     *   * `list` - list items is allowed
                     *   * `download` - download files is allowed
                     *   * `upload` - upload files is allowed
                     *   * `overwrite` - overwrite an existing file, while uploading, is allowed. upload permission is required to allow file overwrite
                     *   * `delete` - delete files or directories is allowed
                     *   * `delete_files` - delete files is allowed
                     *   * `delete_dirs` - delete directories is allowed
                     *   * `rename` - rename files or directories is allowed
                     *   * `rename_files` - rename files is allowed
                     *   * `rename_dirs` - rename directories is allowed
                     *   * `create_dirs` - create directories is allowed
                     *   * `create_symlinks` - create links is allowed
                     *   * `chmod` changing file or directory permissions is allowed
                     *   * `chown` changing file or directory owner and group is allowed
                     *   * `chtimes` changing file or directory access and modification time is allowed
                     *
                     */
                    Permission,
                    .../**
                     * Permissions:
                     *   * `*` - all permissions are granted
                     *   * `list` - list items is allowed
                     *   * `download` - download files is allowed
                     *   * `upload` - upload files is allowed
                     *   * `overwrite` - overwrite an existing file, while uploading, is allowed. upload permission is required to allow file overwrite
                     *   * `delete` - delete files or directories is allowed
                     *   * `delete_files` - delete files is allowed
                     *   * `delete_dirs` - delete directories is allowed
                     *   * `rename` - rename files or directories is allowed
                     *   * `rename_files` - rename files is allowed
                     *   * `rename_dirs` - rename directories is allowed
                     *   * `create_dirs` - create directories is allowed
                     *   * `create_symlinks` - create links is allowed
                     *   * `chmod` changing file or directory permissions is allowed
                     *   * `chown` changing file or directory owner and group is allowed
                     *   * `chtimes` changing file or directory access and modification time is allowed
                     *
                     */
                    Permission[]
                ];
            };
            /**
             * Maximum upload bandwidth as KB/s
             */
            upload_bandwidth?: number;
            /**
             * Maximum download bandwidth as KB/s
             */
            download_bandwidth?: number;
            /**
             * Maximum data transfer allowed for uploads as MB
             */
            upload_data_transfer?: number;
            /**
             * Maximum data transfer allowed for downloads as MB
             */
            download_data_transfer?: number;
            /**
             * Maximum total data transfer as MB
             */
            total_data_transfer?: number;
            /**
             * Account expiration in number of days from creation. 0 means no expiration
             */
            expires_in?: number;
            filters?: /* Additional user options */ BaseUserFilters;
            filesystem?: /* Storage filesystem details */ FilesystemConfig;
        }
        export interface HTTPFsConfig {
            /**
             * HTTP/S endpoint URL. SFTPGo will use this URL as base, for example for the `stat` API, SFTPGo will add `/stat/{name}`
             */
            endpoint?: string;
            username?: string;
            password?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            api_key?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            skip_tls_verify?: boolean;
            /**
             * Defines how to check if this config points to the same server as another config. If different configs point to the same server the renaming between the fs configs is allowed:
             *  * `0` username and endpoint must match. This is the default
             *  * `1` only the endpoint must match
             *
             */
            equality_check_mode?: 0 | 1;
        }
        export interface HTTPPart {
            name?: string;
            /**
             * Additional headers. Content-Disposition header is automatically set. Content-Type header is automatically detect for files to attach
             */
            headers?: KeyValue[];
            /**
             * path to the file to be sent as an attachment
             */
            filepath?: string;
            body?: string;
        }
        /**
         * User specific hook overrides
         */
        export interface HooksFilter {
            /**
             * If true, the external auth hook, if defined, will not be executed
             * example:
             * false
             */
            external_auth_disabled?: boolean;
            /**
             * If true, the pre-login hook, if defined, will not be executed
             * example:
             * false
             */
            pre_login_disabled?: boolean;
            /**
             * If true, the check password hook, if defined, will not be executed
             * example:
             * false
             */
            check_password_disabled?: boolean;
        }
        export interface IPListEntry {
            /**
             * IP address or network in CIDR format, for example `192.168.1.2/32`, `192.168.0.0/24`, `2001:db8::/32`
             */
            ipornet?: string;
            /**
             * optional description
             */
            description?: string;
            type?: /**
             * IP List types:
             *   * `1` - allow list
             *   * `2` - defender
             *   * `3` - rate limiter safe list
             *
             */
            IPListType;
            mode?: /**
             * IP list modes
             *   * `1` - allow
             *   * `2` - deny, supported for defender list type only
             *
             */
            IPListMode;
            /**
             * Defines the protocol the entry applies to. `0` means all the supported protocols, 1 SSH, 2 FTP, 4 WebDAV, 8 HTTP. Protocols can be combined, for example 3 means SSH and FTP
             */
            protocols?: number;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in millisecond
             */
            updated_at?: number; // int64
        }
        /**
         * IP list modes
         *   * `1` - allow
         *   * `2` - deny, supported for defender list type only
         *
         */
        export type IPListMode = 1 | 2;
        /**
         * IP List types:
         *   * `1` - allow list
         *   * `2` - defender
         *   * `3` - rate limiter safe list
         *
         */
        export type IPListType = 1 | 2 | 3;
        export interface KeyValue {
            key?: string;
            value?: string;
        }
        export interface LogEvent {
            id?: string;
            /**
             * unix timestamp in nanoseconds
             */
            timestamp?: number; // int64
            event?: /**
             * Event status:
             *   * `1` - Login failed
             *   * `2` - Login failed non-existent user
             *   * `3` - No login tried
             *   * `4` - Algorithm negotiation failed
             *
             */
            LogEventType;
            protocol?: /**
             * Protocols:
             *   * `SSH` - SSH commands
             *   * `SFTP` - SFTP protocol
             *   * `SCP` - SCP protocol
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV
             *   * `HTTP` - WebClient/REST API
             *   * `HTTPShare` - the event is generated in a public share
             *   * `DataRetention` - the event is generated by a data retention check
             *   * `EventAction` - the event is generated by an EventManager action
             *   * `OIDC` - OpenID Connect
             *
             */
            EventProtocols;
            username?: string;
            ip?: string;
            message?: string;
            role?: string;
            instance_id?: string;
        }
        /**
         * Event status:
         *   * `1` - Login failed
         *   * `2` - Login failed non-existent user
         *   * `3` - No login tried
         *   * `4` - Algorithm negotiation failed
         *
         */
        export type LogEventType = 1 | 2 | 3 | 4;
        /**
         * Available login methods. To enable multi-step authentication you have to allow only multi-step login methods
         *   * `publickey`
         *   * `password`, password for all the supported protocols
         *   * `password-over-SSH`, password over SSH protocol (SSH/SFTP/SCP)
         *   * `keyboard-interactive`
         *   * `publickey+password` - multi-step auth: public key and password
         *   * `publickey+keyboard-interactive` - multi-step auth: public key and keyboard interactive
         *   * `TLSCertificate`
         *   * `TLSCertificate+password` - multi-step auth: TLS client certificate and password
         *
         */
        export type LoginMethods = "publickey" | "password" | "password-over-SSH" | "keyboard-interactive" | "publickey+password" | "publickey+keyboard-interactive" | "TLSCertificate" | "TLSCertificate+password";
        /**
         * Protocols:
         *   * `SSH` - includes both SFTP and SSH commands
         *   * `FTP` - plain FTP and FTPES/FTPS
         *   * `HTTP` - WebClient/REST API
         *
         */
        export type MFAProtocols = "SSH" | "FTP" | "HTTP";
        export interface MFAStatus {
            is_active?: boolean;
            totp_configs?: TOTPConfig[];
        }
        export interface MetadataCheck {
            /**
             * username to which the check refers
             */
            username?: string;
            /**
             * check start time as unix timestamp in milliseconds
             */
            start_time?: number; // int64
        }
        export interface OSFsConfig {
            /**
             * The read buffer size, as MB, to use for downloads. 0 means no buffering, that's fine in most use cases.
             */
            read_buffer_size?: number;
            /**
             * The write buffer size, as MB, to use for uploads. 0 means no buffering, that's fine in most use cases.
             */
            write_buffer_size?: number;
        }
        export interface PassiveIPOverride {
            networks?: string[];
            ip?: string;
        }
        export interface PatternsFilter {
            /**
             * virtual path as seen by users, if no other specific filter is defined, the filter applies for sub directories too. For example if filters are defined for the paths "/" and "/sub" then the filters for "/" are applied for any file outside the "/sub" directory
             */
            path?: string;
            /**
             * list of, case insensitive, allowed shell like patterns. Allowed patterns are evaluated before the denied ones
             * example:
             * [
             *   "*.jpg",
             *   "a*b?.png"
             * ]
             */
            allowed_patterns?: string[];
            /**
             * list of, case insensitive, denied shell like patterns
             * example:
             * [
             *   "*.zip"
             * ]
             */
            denied_patterns?: string[];
            /**
             * Policies for denied patterns
             *   * `0` - default policy. Denied files/directories matching the filters are visible in directory listing but cannot be uploaded/downloaded/overwritten/renamed
             *   * `1` - deny policy hide. This policy applies the same restrictions as the default one and denied files/directories matching the filters will also be hidden in directory listing. This mode may cause performance issues for large directories
             *
             */
            deny_policy?: 0 | 1;
        }
        /**
         * Permissions:
         *   * `*` - all permissions are granted
         *   * `list` - list items is allowed
         *   * `download` - download files is allowed
         *   * `upload` - upload files is allowed
         *   * `overwrite` - overwrite an existing file, while uploading, is allowed. upload permission is required to allow file overwrite
         *   * `delete` - delete files or directories is allowed
         *   * `delete_files` - delete files is allowed
         *   * `delete_dirs` - delete directories is allowed
         *   * `rename` - rename files or directories is allowed
         *   * `rename_files` - rename files is allowed
         *   * `rename_dirs` - rename directories is allowed
         *   * `create_dirs` - create directories is allowed
         *   * `create_symlinks` - create links is allowed
         *   * `chmod` changing file or directory permissions is allowed
         *   * `chown` changing file or directory owner and group is allowed
         *   * `chtimes` changing file or directory access and modification time is allowed
         *
         */
        export type Permission = "*" | "list" | "download" | "upload" | "overwrite" | "delete" | "delete_files" | "delete_dirs" | "rename" | "rename_files" | "rename_dirs" | "create_dirs" | "create_symlinks" | "chmod" | "chown" | "chtimes";
        export interface ProviderEvent {
            id?: string;
            /**
             * unix timestamp in nanoseconds
             */
            timestamp?: number; // int64
            action?: ProviderEventAction;
            username?: string;
            ip?: string;
            object_type?: ProviderEventObjectType;
            object_name?: string;
            /**
             * base64 of the JSON serialized object with sensitive fields removed
             */
            object_data?: string; // byte
            role?: string;
            instance_id?: string;
        }
        export type ProviderEventAction = "add" | "update" | "delete";
        export type ProviderEventObjectType = "user" | "folder" | "group" | "admin" | "api_key" | "share" | "event_action" | "event_rule" | "role";
        export interface PwdChange {
            current_password?: string;
            new_password?: string;
        }
        export interface QuotaScan {
            /**
             * username to which the quota scan refers
             */
            username?: string;
            /**
             * scan start time as unix timestamp in milliseconds
             */
            start_time?: number; // int64
        }
        export interface QuotaUsage {
            used_quota_size?: number; // int64
            used_quota_files?: number; // int32
        }
        /**
         * Recovery codes to use if the user loses access to their second factor auth device. Each code can only be used once, you should use these codes to login and disable or reset 2FA for your account
         */
        export interface RecoveryCode {
            secret?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            used?: boolean;
        }
        export interface RetentionCheck {
            /**
             * username to which the retention check refers
             */
            username?: string;
            folders?: FolderRetention[];
            /**
             * check start time as unix timestamp in milliseconds
             */
            start_time?: number; // int64
            notifications?: /**
             * Options:
             *   * `Hook` - notify result using the defined hook. A "data_retention_hook" must be defined in your configuration file for this to work
             *   * `Email` - notify results by email. The admin starting the retention check must have an associated email address and the SMTP server must be configured for this to work
             *
             */
            RetentionCheckNotification[];
            /**
             * if the notification method is set to "Email", this is the e-mail address that receives the retention check report. This field is automatically set to the email address associated with the administrator starting the check
             */
            email?: string; // email
        }
        /**
         * Options:
         *   * `Hook` - notify result using the defined hook. A "data_retention_hook" must be defined in your configuration file for this to work
         *   * `Email` - notify results by email. The admin starting the retention check must have an associated email address and the SMTP server must be configured for this to work
         *
         */
        export type RetentionCheckNotification = "Hook" | "Email";
        export interface Role {
            id?: number; // int32
            /**
             * name is unique
             */
            name?: string;
            /**
             * optional description
             */
            description?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            /**
             * list of usernames associated with this group
             */
            users?: string[];
            /**
             * list of admins usernames associated with this group
             */
            admins?: string[];
        }
        /**
         * S3 Compatible Object Storage configuration details
         */
        export interface S3Config {
            bucket?: string;
            region?: string;
            access_key?: string;
            access_secret?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * Optional IAM Role ARN to assume
             */
            role_arn?: string;
            /**
             * optional endpoint
             */
            endpoint?: string;
            storage_class?: string;
            /**
             * The canned ACL to apply to uploaded objects. Leave empty to use the default ACL. For more information and available ACLs, see here: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl
             */
            acl?: string;
            /**
             * the buffer size (in MB) to use for multipart uploads. The minimum allowed part size is 5MB, and if this value is set to zero, the default value (5MB) for the AWS SDK will be used. The minimum allowed value is 5.
             */
            upload_part_size?: number;
            /**
             * the number of parts to upload in parallel. If this value is set to zero, the default value (5) will be used
             */
            upload_concurrency?: number;
            /**
             * the maximum time allowed, in seconds, to upload a single chunk (the chunk size is defined via "upload_part_size"). 0 means no timeout
             */
            upload_part_max_time?: number;
            /**
             * the buffer size (in MB) to use for multipart downloads. The minimum allowed part size is 5MB, and if this value is set to zero, the default value (5MB) for the AWS SDK will be used. The minimum allowed value is 5. Ignored for partial downloads
             */
            download_part_size?: number;
            /**
             * the number of parts to download in parallel. If this value is set to zero, the default value (5) will be used. Ignored for partial downloads
             */
            download_concurrency?: number;
            /**
             * the maximum time allowed, in seconds, to download a single chunk (the chunk size is defined via "download_part_size"). 0 means no timeout. Ignored for partial downloads.
             */
            download_part_max_time?: number;
            /**
             * Set this to "true" to force the request to use path-style addressing, i.e., "http://s3.amazonaws.com/BUCKET/KEY". By default, the S3 client will use virtual hosted bucket addressing when possible ("http://BUCKET.s3.amazonaws.com/KEY")
             */
            force_path_style?: boolean;
            /**
             * key_prefix is similar to a chroot directory for a local filesystem. If specified the user will only see contents that starts with this prefix and so you can restrict access to a specific virtual folder. The prefix, if not empty, must not start with "/" and must end with "/". If empty the whole bucket contents will be available
             * example:
             * folder/subfolder/
             */
            key_prefix?: string;
        }
        export interface SFTPFsConfig {
            /**
             * remote SFTP endpoint as host:port
             */
            endpoint?: string;
            /**
             * you can specify a password or private key or both. In the latter case the private key will be tried first.
             */
            username?: string;
            password?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            private_key?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            key_passphrase?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * SHA256 fingerprints to use for host key verification. If you don't provide any fingerprint the remote host key will not be verified, this is a security risk
             */
            fingerprints?: string[];
            /**
             * Specifying a prefix you can restrict all operations to a given path within the remote SFTP server.
             */
            prefix?: string;
            /**
             * Concurrent reads are safe to use and disabling them will degrade performance. Some servers automatically delete files once they are downloaded. Using concurrent reads is problematic with such servers.
             */
            disable_concurrent_reads?: boolean;
            /**
             * The size of the buffer (in MB) to use for transfers. By enabling buffering, the reads and writes, from/to the remote SFTP server, are split in multiple concurrent requests and this allows data to be transferred at a faster rate, over high latency networks, by overlapping round-trip times. With buffering enabled, resuming uploads is not supported and a file cannot be opened for both reading and writing at the same time. 0 means disabled.
             * example:
             * 2
             */
            buffer_size?: number;
            /**
             * Defines how to check if this config points to the same server as another config. If different configs point to the same server the renaming between the fs configs is allowed:
             *  * `0` username and endpoint must match. This is the default
             *  * `1` only the endpoint must match
             *
             */
            equality_check_mode?: 0 | 1;
        }
        export type SSHAuthentications = "publickey" | "password" | "keyboard-interactive" | "publickey+password" | "publickey+keyboard-interactive";
        export interface SSHBinding {
            /**
             * TCP address the server listen on
             */
            address?: string;
            /**
             * the port used for serving requests
             */
            port?: number;
            /**
             * apply the proxy configuration, if any
             */
            apply_proxy_config?: boolean;
        }
        export interface SSHHostKey {
            path?: string;
            fingerprint?: string;
            algorithms?: string[];
        }
        export interface SSHServiceStatus {
            is_active?: boolean;
            bindings?: SSHBinding[] | null;
            host_keys?: SSHHostKey[] | null;
            ssh_commands?: string[];
            authentications?: SSHAuthentications[];
            public_key_algorithms?: string[];
            macs?: string[];
            kex_algorithms?: string[];
            ciphers?: string[];
        }
        export interface Schedule {
            hour?: string;
            day_of_week?: string;
            day_of_month?: string;
            month?: string;
        }
        /**
         * The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved
         */
        export interface Secret {
            /**
             * Set to "Plain" to add or update an existing secret, set to "Redacted" to preserve the existing value
             */
            status?: "Plain" | "AES-256-GCM" | "Secretbox" | "GCP" | "AWS" | "VaultTransit" | "AzureKeyVault" | "Redacted";
            payload?: string;
            key?: string;
            additional_data?: string;
            /**
             * 1 means encrypted using a master key
             */
            mode?: number;
        }
        export interface ServicesStatus {
            ssh?: SSHServiceStatus;
            ftp?: FTPServiceStatus;
            webdav?: WebDAVServiceStatus;
            data_provider?: DataProviderStatus;
            defender?: {
                is_active?: boolean;
            };
            mfa?: MFAStatus;
            allow_list?: {
                is_active?: boolean;
            };
            rate_limiters?: {
                is_active?: boolean;
                protocols?: string[];
            };
        }
        export interface Share {
            /**
             * auto-generated unique share identifier
             */
            id?: string;
            name?: string;
            /**
             * optional description
             */
            description?: string;
            scope?: /**
             * Options:
             *   * `1` - read scope
             *   * `2` - write scope
             *
             */
            ShareScope;
            /**
             * paths to files or directories, for share scope write this array must contain exactly one directory. Paths will not be validated on save so you can also create them after creating the share
             * example:
             * [
             *   "/dir1",
             *   "/dir2/file.txt",
             *   "/dir3/subdir"
             * ]
             */
            paths?: string[];
            username?: string;
            /**
             * creation time as unix timestamp in milliseconds
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            /**
             * last use time as unix timestamp in milliseconds
             */
            last_use_at?: number; // int64
            /**
             * optional share expiration, as unix timestamp in milliseconds. 0 means no expiration
             */
            expires_at?: number; // int64
            /**
             * optional password to protect the share. The special value "[**redacted**]" means that a password has been set, you can use this value if you want to preserve the current password when you update a share
             */
            password?: string;
            /**
             * maximum allowed access tokens. 0 means no limit
             */
            max_tokens?: number;
            used_tokens?: number;
            /**
             * Limit the share availability to these IP/Mask. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32". An empty list means no restrictions
             * example:
             * [
             *   "192.0.2.0/24",
             *   "2001:db8::/32"
             * ]
             */
            allow_from?: string[];
        }
        /**
         * Options:
         *   * `1` - read scope
         *   * `2` - write scope
         *
         */
        export type ShareScope = 1 | 2;
        /**
         * Protocols:
         *   * `SSH` - includes both SFTP and SSH commands
         *   * `FTP` - plain FTP and FTPES/FTPS
         *   * `DAV` - WebDAV over HTTP/HTTPS
         *   * `HTTP` - WebClient/REST API
         *
         */
        export type SupportedProtocols = "SSH" | "FTP" | "DAV" | "HTTP";
        /**
         * TLS version:
         *   * `12` - TLS 1.2
         *   * `13` - TLS 1.3
         *
         */
        export type TLSVersions = 12 | 13;
        export interface TOTPConfig {
            name?: string;
            issuer?: string;
            algo?: /* Supported HMAC algorithms for Time-based one time passwords */ TOTPHMacAlgo;
        }
        /**
         * Supported HMAC algorithms for Time-based one time passwords
         */
        export type TOTPHMacAlgo = "sha1" | "sha256" | "sha512";
        export interface Token {
            access_token?: string;
            expires_at?: string; // date-time
        }
        export interface Transfer {
            /**
             * Operations:
             *   * `upload`
             *   * `download`
             *
             */
            operation_type?: "upload" | "download";
            /**
             * file path for the upload/download
             */
            path?: string;
            /**
             * start time as unix timestamp in milliseconds
             */
            start_time?: number; // int64
            /**
             * bytes transferred
             */
            size?: number; // int64
        }
        export interface TransferQuotaUsage {
            /**
             * The value must be specified as bytes
             */
            used_upload_data_transfer?: number; // int64
            /**
             * The value must be specified as bytes
             */
            used_download_data_transfer?: number; // int64
        }
        export interface User {
            id?: number; // int32
            /**
             * status:
             *   * `0` user is disabled, login is not allowed
             *   * `1` user is enabled
             *
             */
            status?: 0 | 1;
            /**
             * username is unique
             */
            username?: string;
            email?: string; // email
            /**
             * optional description, for example the user full name
             */
            description?: string;
            /**
             * expiration date as unix timestamp in milliseconds. An expired account cannot login. 0 means no expiration
             */
            expiration_date?: number; // int64
            /**
             * If the password has no known hashing algo prefix it will be stored, by default, using bcrypt, argon2id is supported too. You can send a password hashed as bcrypt ($2a$ prefix), argon2id, pbkdf2 or unix crypt and it will be stored as is. For security reasons this field is omitted when you search/get users
             */
            password?: string; // password
            /**
             * Public keys in OpenSSH format.
             */
            public_keys?: string[];
            /**
             * Indicates whether the password is set
             */
            has_password?: boolean;
            /**
             * path to the user home directory. The user cannot upload or download files outside this directory. SFTPGo tries to automatically create this folder if missing. Must be an absolute path
             */
            home_dir?: string;
            /**
             * mapping between virtual SFTPGo paths and virtual folders
             */
            virtual_folders?: /* A virtual folder is a mapping between a SFTPGo virtual path and a filesystem path outside the user home directory. The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory. The parent directory for the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login. */ VirtualFolder[];
            /**
             * if you run SFTPGo as root user, the created files and directories will be assigned to this uid. 0 means no change, the owner will be the user that runs SFTPGo. Ignored on windows
             */
            uid?: number; // int32
            /**
             * if you run SFTPGo as root user, the created files and directories will be assigned to this gid. 0 means no change, the group will be the one of the user that runs SFTPGo. Ignored on windows
             */
            gid?: number; // int32
            /**
             * Limit the sessions that a user can open. 0 means unlimited
             */
            max_sessions?: number; // int32
            /**
             * Quota as size in bytes. 0 means unlimited. Please note that quota is updated if files are added/removed via SFTPGo otherwise a quota scan or a manual quota update is needed
             */
            quota_size?: number; // int64
            /**
             * Quota as number of files. 0 means unlimited. Please note that quota is updated if files are added/removed via SFTPGo otherwise a quota scan or a manual quota update is needed
             */
            quota_files?: number; // int32
            /**
             * hash map with directory as key and an array of permissions as value. Directories must be absolute paths, permissions for root directory ("/") are required
             * example:
             * {
             *   "/": [
             *     "*"
             *   ],
             *   "/somedir": [
             *     "list",
             *     "download"
             *   ]
             * }
             */
            permissions?: {
                [name: string]: [
                    /**
                     * Permissions:
                     *   * `*` - all permissions are granted
                     *   * `list` - list items is allowed
                     *   * `download` - download files is allowed
                     *   * `upload` - upload files is allowed
                     *   * `overwrite` - overwrite an existing file, while uploading, is allowed. upload permission is required to allow file overwrite
                     *   * `delete` - delete files or directories is allowed
                     *   * `delete_files` - delete files is allowed
                     *   * `delete_dirs` - delete directories is allowed
                     *   * `rename` - rename files or directories is allowed
                     *   * `rename_files` - rename files is allowed
                     *   * `rename_dirs` - rename directories is allowed
                     *   * `create_dirs` - create directories is allowed
                     *   * `create_symlinks` - create links is allowed
                     *   * `chmod` changing file or directory permissions is allowed
                     *   * `chown` changing file or directory owner and group is allowed
                     *   * `chtimes` changing file or directory access and modification time is allowed
                     *
                     */
                    Permission,
                    .../**
                     * Permissions:
                     *   * `*` - all permissions are granted
                     *   * `list` - list items is allowed
                     *   * `download` - download files is allowed
                     *   * `upload` - upload files is allowed
                     *   * `overwrite` - overwrite an existing file, while uploading, is allowed. upload permission is required to allow file overwrite
                     *   * `delete` - delete files or directories is allowed
                     *   * `delete_files` - delete files is allowed
                     *   * `delete_dirs` - delete directories is allowed
                     *   * `rename` - rename files or directories is allowed
                     *   * `rename_files` - rename files is allowed
                     *   * `rename_dirs` - rename directories is allowed
                     *   * `create_dirs` - create directories is allowed
                     *   * `create_symlinks` - create links is allowed
                     *   * `chmod` changing file or directory permissions is allowed
                     *   * `chown` changing file or directory owner and group is allowed
                     *   * `chtimes` changing file or directory access and modification time is allowed
                     *
                     */
                    Permission[]
                ];
            };
            used_quota_size?: number; // int64
            used_quota_files?: number; // int32
            /**
             * Last quota update as unix timestamp in milliseconds
             */
            last_quota_update?: number; // int64
            /**
             * Maximum upload bandwidth as KB/s, 0 means unlimited
             */
            upload_bandwidth?: number;
            /**
             * Maximum download bandwidth as KB/s, 0 means unlimited
             */
            download_bandwidth?: number;
            /**
             * Maximum data transfer allowed for uploads as MB. 0 means no limit
             */
            upload_data_transfer?: number;
            /**
             * Maximum data transfer allowed for downloads as MB. 0 means no limit
             */
            download_data_transfer?: number;
            /**
             * Maximum total data transfer as MB. 0 means unlimited. You can set a total data transfer instead of the individual values for uploads and downloads
             */
            total_data_transfer?: number;
            /**
             * Uploaded size, as bytes, since the last reset
             */
            used_upload_data_transfer?: number;
            /**
             * Downloaded size, as bytes, since the last reset
             */
            used_download_data_transfer?: number;
            /**
             * creation time as unix timestamp in milliseconds. It will be 0 for users created before v2.2.0
             */
            created_at?: number; // int64
            /**
             * last update time as unix timestamp in milliseconds
             */
            updated_at?: number; // int64
            /**
             * Last user login as unix timestamp in milliseconds. It is saved at most once every 10 minutes
             */
            last_login?: number; // int64
            /**
             * first download time as unix timestamp in milliseconds
             */
            first_download?: number; // int64
            /**
             * first upload time as unix timestamp in milliseconds
             */
            first_upload?: number; // int64
            /**
             * last password change time as unix timestamp in milliseconds
             */
            last_password_change?: number; // int64
            filters?: /* Additional user options */ UserFilters;
            filesystem?: /* Storage filesystem details */ FilesystemConfig;
            /**
             * Free form text field for external systems
             */
            additional_info?: string;
            groups?: GroupMapping[];
            /**
             * This field is passed to the pre-login hook if custom OIDC token fields have been configured. Field values can be of any type (this is a free form object) and depend on the type of the configured OIDC token fields
             */
            oidc_custom_fields?: {
                [name: string]: any;
            };
            role?: string;
        }
        /**
         * Additional user options
         */
        export interface UserFilters {
            /**
             * only clients connecting from these IP/Mask are allowed. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32"
             * example:
             * [
             *   "192.0.2.0/24",
             *   "2001:db8::/32"
             * ]
             */
            allowed_ip?: string[];
            /**
             * clients connecting from these IP/Mask are not allowed. Denied rules are evaluated before allowed ones
             * example:
             * [
             *   "172.16.0.0/16"
             * ]
             */
            denied_ip?: string[];
            /**
             * if null or empty any available login method is allowed
             */
            denied_login_methods?: /**
             * Available login methods. To enable multi-step authentication you have to allow only multi-step login methods
             *   * `publickey`
             *   * `password`, password for all the supported protocols
             *   * `password-over-SSH`, password over SSH protocol (SSH/SFTP/SCP)
             *   * `keyboard-interactive`
             *   * `publickey+password` - multi-step auth: public key and password
             *   * `publickey+keyboard-interactive` - multi-step auth: public key and keyboard interactive
             *   * `TLSCertificate`
             *   * `TLSCertificate+password` - multi-step auth: TLS client certificate and password
             *
             */
            LoginMethods[];
            /**
             * if null or empty any available protocol is allowed
             */
            denied_protocols?: /**
             * Protocols:
             *   * `SSH` - includes both SFTP and SSH commands
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV over HTTP/HTTPS
             *   * `HTTP` - WebClient/REST API
             *
             */
            SupportedProtocols[];
            /**
             * filters based on shell like file patterns. These restrictions do not apply to files listing for performance reasons, so a denied file cannot be downloaded/overwritten/renamed but it will still be in the list of files. Please note that these restrictions can be easily bypassed
             */
            file_patterns?: PatternsFilter[];
            /**
             * maximum allowed size, as bytes, for a single file upload. The upload will be aborted if/when the size of the file being sent exceeds this limit. 0 means unlimited. This restriction does not apply for SSH system commands such as `git` and `rsync`
             */
            max_upload_file_size?: number; // int64
            /**
             * defines the TLS certificate field to use as username. For FTP clients it must match the name provided using the "USER" command. For WebDAV, if no username is provided, the CN will be used as username. For WebDAV clients it must match the implicit or provided username. Ignored if mutual TLS is disabled. Currently the only supported value is `CommonName`
             */
            tls_username?: string;
            hooks?: /* User specific hook overrides */ HooksFilter;
            /**
             * Disable checks for existence and automatic creation of home directory and virtual folders. SFTPGo requires that the user's home directory, virtual folder root, and intermediate paths to virtual folders exist to work properly. If you already know that the required directories exist, disabling these checks will speed up login. You could, for example, disable these checks after the first login
             * example:
             * false
             */
            disable_fs_checks?: boolean;
            /**
             * WebClient/user REST API related configuration options
             */
            web_client?: /**
             * Options:
             *   * `publickey-change-disabled` - changing SSH public keys is not allowed
             *   * `write-disabled` - upload, rename, delete are not allowed even if the user has permissions for these actions
             *   * `mfa-disabled` - enabling multi-factor authentication is not allowed. This option cannot be set if the user has MFA already enabled
             *   * `password-change-disabled` - changing password is not allowed
             *   * `api-key-auth-change-disabled` - enabling/disabling API key authentication is not allowed
             *   * `info-change-disabled` - changing info such as email and description is not allowed
             *   * `shares-disabled` - sharing files and directories with external users is not allowed
             *   * `password-reset-disabled` - resetting the password is not allowed
             *   * `shares-without-password-disabled` - creating shares without password protection is not allowed
             *
             */
            WebClientOptions[];
            /**
             * API key authentication allows to impersonate this user with an API key
             */
            allow_api_key_auth?: boolean;
            user_type?: /* This is an hint for authentication plugins. It is ignored when using SFTPGo internal authentication */ UserType;
            bandwidth_limits?: BandwidthLimit[];
            /**
             * Defines the cache time, in seconds, for users authenticated using an external auth hook. 0 means no cache
             */
            external_auth_cache_time?: number;
            /**
             * Specifies an alternate starting directory. If not set, the default is "/". This option is supported for SFTP/SCP, FTP and HTTP (WebClient/REST API) protocols. Relative paths will use this directory as base.
             */
            start_directory?: string;
            /**
             * Defines protocols that require two factor authentication
             */
            two_factor_protocols?: /**
             * Protocols:
             *   * `SSH` - includes both SFTP and SSH commands
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `HTTP` - WebClient/REST API
             *
             */
            MFAProtocols[];
            /**
             * Set to `1` to require TLS for both data and control connection. his setting is useful if you want to allow both encrypted and plain text FTP sessions globally and then you want to require encrypted sessions on a per-user basis. It has no effect if TLS is already required for all users in the configuration file.
             */
            ftp_security?: 0 | 1;
            /**
             * If enabled the user can login with any password or no password at all. Anonymous users are supported for FTP and WebDAV protocols and permissions will be automatically set to "list" and "download" (read only)
             */
            is_anonymous?: boolean;
            /**
             * Defines the default expiration for newly created shares as number of days. 0 means no expiration
             */
            default_shares_expiration?: number;
            /**
             * Defines the maximum allowed expiration, as a number of days, when a user creates or updates a share. 0 means no expiration
             */
            max_shares_expiration?: number;
            /**
             * The password expires after the defined number of days. 0 means no expiration
             */
            password_expiration?: number;
            /**
             * User must change password from WebClient/REST API at next login
             */
            require_password_change?: boolean;
            totp_config?: UserTOTPConfig;
            recovery_codes?: /* Recovery codes to use if the user loses access to their second factor auth device. Each code can only be used once, you should use these codes to login and disable or reset 2FA for your account */ RecoveryCode[];
        }
        export interface UserProfile {
            email?: string; // email
            description?: string;
            /**
             * If enabled, you can impersonate this user, in REST API, using an API key. If disabled user credentials are required for impersonation
             */
            allow_api_key_auth?: boolean;
            public_keys?: string[];
        }
        export interface UserTOTPConfig {
            enabled?: boolean;
            /**
             * This name must be defined within the "totp" section of the SFTPGo configuration file. You will be unable to save a user/admin referencing a missing config_name
             */
            config_name?: string;
            secret?: /* The secret is encrypted before saving, so to set a new secret you must provide a payload and set the status to "Plain". The encryption key and additional data will be generated automatically. If you set the status to "Redacted" the existing secret will be preserved */ Secret;
            /**
             * TOTP will be required for the specified protocols. SSH protocol (SFTP/SCP/SSH commands) will ask for the TOTP passcode if the client uses keyboard interactive authentication. FTP has no standard way to support two factor authentication, if you enable the FTP support, you have to add the TOTP passcode after the password. For example if your password is "password" and your one time passcode is "123456" you have to use "password123456" as password. WebDAV is not supported since each single request must be authenticated and a passcode cannot be reused.
             */
            protocols?: /**
             * Protocols:
             *   * `SSH` - includes both SFTP and SSH commands
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `HTTP` - WebClient/REST API
             *
             */
            MFAProtocols[];
        }
        /**
         * This is an hint for authentication plugins. It is ignored when using SFTPGo internal authentication
         */
        export type UserType = "" | "LDAPUser" | "OSUser";
        export interface VersionInfo {
            version?: string;
            build_date?: string;
            commit_hash?: string;
            /**
             * Features for the current build. Available features are `portable`, `bolt`, `mysql`, `sqlite`, `pgsql`, `s3`, `gcs`, `azblob`, `metrics`, `unixcrypt`. If a feature is available it has a `+` prefix, otherwise a `-` prefix
             */
            features?: string[];
        }
        /**
         * A virtual folder is a mapping between a SFTPGo virtual path and a filesystem path outside the user home directory. The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory. The parent directory for the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login.
         */
        export interface VirtualFolder {
            id?: number; // int32
            /**
             * unique name for this virtual folder
             */
            name?: string;
            /**
             * absolute filesystem path to use as virtual folder
             */
            mapped_path?: string;
            /**
             * optional description
             */
            description?: string;
            used_quota_size?: number; // int64
            used_quota_files?: number; // int32
            /**
             * Last quota update as unix timestamp in milliseconds
             */
            last_quota_update?: number; // int64
            /**
             * list of usernames associated with this virtual folder
             */
            users?: string[];
            filesystem?: /* Storage filesystem details */ FilesystemConfig;
            virtual_path: string;
            /**
             * Quota as size in bytes. 0 means unlimited, -1 means included in user quota. Please note that quota is updated if files are added/removed via SFTPGo otherwise a quota scan or a manual quota update is needed
             */
            quota_size?: number; // int64
            /**
             * Quota as number of files. 0 means unlimited, , -1 means included in user quota. Please note that quota is updated if files are added/removed via SFTPGo otherwise a quota scan or a manual quota update is needed
             */
            quota_files?: number; // int32
        }
        /**
         * Options:
         *   * `publickey-change-disabled` - changing SSH public keys is not allowed
         *   * `write-disabled` - upload, rename, delete are not allowed even if the user has permissions for these actions
         *   * `mfa-disabled` - enabling multi-factor authentication is not allowed. This option cannot be set if the user has MFA already enabled
         *   * `password-change-disabled` - changing password is not allowed
         *   * `api-key-auth-change-disabled` - enabling/disabling API key authentication is not allowed
         *   * `info-change-disabled` - changing info such as email and description is not allowed
         *   * `shares-disabled` - sharing files and directories with external users is not allowed
         *   * `password-reset-disabled` - resetting the password is not allowed
         *   * `shares-without-password-disabled` - creating shares without password protection is not allowed
         *
         */
        export type WebClientOptions = "publickey-change-disabled" | "write-disabled" | "mfa-disabled" | "password-change-disabled" | "api-key-auth-change-disabled" | "info-change-disabled" | "shares-disabled" | "password-reset-disabled" | "shares-without-password-disabled";
        export interface WebDAVBinding {
            /**
             * TCP address the server listen on
             */
            address?: string;
            /**
             * the port used for serving requests
             */
            port?: number;
            enable_https?: boolean;
            min_tls_version?: /**
             * TLS version:
             *   * `12` - TLS 1.2
             *   * `13` - TLS 1.3
             *
             */
            TLSVersions;
            /**
             * 1 means that client certificate authentication is required in addition to HTTP basic authentication
             */
            client_auth_type?: number;
            /**
             * List of supported cipher suites for TLS version 1.2. If empty  a default list of secure cipher suites is used, with a preference order based on hardware performance
             */
            tls_cipher_suites?: string[];
            /**
             * Prefix for WebDAV resources, if empty WebDAV resources will be available at the `/` URI
             */
            prefix?: string;
            /**
             * List of IP addresses and IP ranges allowed to set proxy headers
             */
            proxy_allowed?: string[];
        }
        export interface WebDAVServiceStatus {
            is_active?: boolean;
            bindings?: WebDAVBinding[] | null;
        }
    }
}
declare namespace Paths {
    namespace AddAdmin {
        export type RequestBody = Components.Schemas.Admin;
        namespace Responses {
            export type $201 = Components.Schemas.Admin;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddApiKey {
        export type RequestBody = Components.Schemas.APIKey;
        namespace Responses {
            export interface $201 {
                /**
                 * example:
                 * API key created. This is the only time the API key is visible, please save it.
                 */
                mesage?: string;
                /**
                 * generated API key
                 */
                key?: string;
            }
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddEventAction {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        export type RequestBody = Components.Schemas.BaseEventAction;
        namespace Responses {
            export type $201 = Components.Schemas.BaseEventAction;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddEventRule {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        export type RequestBody = Components.Schemas.EventRuleMinimal;
        namespace Responses {
            export type $201 = Components.Schemas.EventRule;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddFolder {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        export type RequestBody = /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ Components.Schemas.BaseVirtualFolder;
        namespace Responses {
            export type $201 = /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ Components.Schemas.BaseVirtualFolder;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddGroup {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        export type RequestBody = Components.Schemas.Group;
        namespace Responses {
            export type $201 = Components.Schemas.Group;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddIpListEntry {
        export type RequestBody = Components.Schemas.IPListEntry;
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddRole {
        export type RequestBody = Components.Schemas.Role;
        namespace Responses {
            export type $201 = Components.Schemas.Role;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddShare {
        export type RequestBody = Components.Schemas.Share;
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AddUser {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        export type RequestBody = Components.Schemas.User;
        namespace Responses {
            export type $201 = Components.Schemas.User;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AdminForgotPassword {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace AdminResetPassword {
        export interface RequestBody {
            code?: string;
            password?: string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Admins$Username {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Admins$Username2faDisable {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Admins$UsernameForgotPassword {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Admins$UsernameResetPassword {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Apikeys$Id {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace ChangeAdminPassword {
        export type RequestBody = Components.Schemas.PwdChange;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace ChangeUserPassword {
        export type RequestBody = Components.Schemas.PwdChange;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace ClientLogout {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace CloseConnection {
        namespace Parameters {
            export type ConnectionID = string;
        }
        export interface PathParameters {
            connectionID: Parameters.ConnectionID;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace CreateUserDir {
        namespace Parameters {
            export type MkdirParents = boolean;
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            mkdir_parents?: Parameters.MkdirParents;
        }
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace CreateUserFile {
        export interface HeaderParameters {
            "X-SFTPGO-MTIME"?: Parameters.XSFTPGOMTIME;
        }
        namespace Parameters {
            export type MkdirParents = boolean;
            export type Path = string;
            export type XSFTPGOMTIME = number;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            mkdir_parents?: Parameters.MkdirParents;
        }
        export type RequestBody = string; // binary
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $413 = Components.Responses.RequestEntityTooLarge;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace CreateUserFiles {
        namespace Parameters {
            export type MkdirParents = boolean;
            export type Path = string;
        }
        export interface QueryParameters {
            path?: Parameters.Path;
            mkdir_parents?: Parameters.MkdirParents;
        }
        export interface RequestBody {
            filenames?: [
                string,
                ...string[]
            ];
        }
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $413 = Components.Responses.RequestEntityTooLarge;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DefenderHosts$Id {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace DeleteAdmin {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteApiKey {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteDefenderHostById {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteEventAction {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteEventRule {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteFolder {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteGroup {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteIpListEntry {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteRole {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteUser {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteUserDir {
        namespace Parameters {
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteUserFile {
        namespace Parameters {
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DeleteUserShare {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DisableAdmin2fa {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DisableUser2fa {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DownloadShareFile {
        namespace Parameters {
            export type Inline = string;
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            inline?: Parameters.Inline;
        }
        namespace Responses {
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace DownloadUserFile {
        namespace Parameters {
            export type Inline = string;
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            inline?: Parameters.Inline;
        }
        namespace Responses {
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Dumpdata {
        namespace Parameters {
            export type Indent = 0 | 1;
            export type OutputData = 0 | 1;
            export type OutputFile = string;
            export type Scopes = Components.Schemas.DumpDataScopes[];
        }
        export interface QueryParameters {
            "output-file"?: Parameters.OutputFile;
            "output-data"?: Parameters.OutputData;
            indent?: Parameters.Indent;
            scopes?: Parameters.Scopes;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse | Components.Schemas.BackupData;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Eventactions$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace Eventrules$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace EventrulesRun$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace FolderQuotaUpdateUsage {
        namespace Parameters {
            /**
             * Update type:
             *   * `add` - add the specified quota limits to the current used ones
             *   * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            export type Mode = "add" | "reset";
        }
        export interface QueryParameters {
            mode?: /**
             * Update type:
             *   * `add` - add the specified quota limits to the current used ones
             *   * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            Parameters.Mode;
        }
        export type RequestBody = Components.Schemas.QuotaUsage;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Folders$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace GenerateAdminRecoveryCodes {
        namespace Responses {
            export type $200 = string[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GenerateAdminTotpSecret {
        export interface RequestBody {
            /**
             * name of the configuration to use to generate the secret
             */
            config_name?: string;
        }
        namespace Responses {
            export interface $200 {
                config_name?: string;
                issuer?: string;
                secret?: string;
                url?: string;
                /**
                 * QR code png encoded as BASE64
                 */
                qr_code?: string; // byte
            }
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GenerateUserRecoveryCodes {
        namespace Responses {
            export type $200 = string[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GenerateUserTotpSecret {
        export interface RequestBody {
            /**
             * name of the configuration to use to generate the secret
             */
            config_name?: string;
        }
        namespace Responses {
            export interface $200 {
                config_name?: string;
                issuer?: string;
                secret?: string;
                /**
                 * QR code png encoded as BASE64
                 */
                qr_code?: string; // byte
            }
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetAdminByUsername {
        namespace Responses {
            export type $200 = Components.Schemas.Admin;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetAdminProfile {
        namespace Responses {
            export type $200 = Components.Schemas.AdminProfile;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetAdminRecoveryCodes {
        namespace Responses {
            export type $200 = /* Recovery codes to use if the user loses access to their second factor auth device. Each code can only be used once, you should use these codes to login and disable or reset 2FA for your account */ Components.Schemas.RecoveryCode[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetAdminTotpConfigs {
        namespace Responses {
            export type $200 = Components.Schemas.TOTPConfig[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetAdmins {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Admin[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetApiKeyById {
        namespace Responses {
            export type $200 = Components.Schemas.APIKey;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetApiKeys {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.APIKey[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetConnections {
        namespace Responses {
            export type $200 = Components.Schemas.ConnectionStatus[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetDefenderHostById {
        namespace Responses {
            export type $200 = Components.Schemas.DefenderEntry;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetDefenderHosts {
        namespace Responses {
            export type $200 = Components.Schemas.DefenderEntry[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetEventActionByName {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        namespace Responses {
            export type $200 = Components.Schemas.BaseEventAction;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetEventActons {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.BaseEventAction[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetEventRileByName {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        namespace Responses {
            export type $200 = Components.Schemas.EventRule;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetEventRules {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.EventRule[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetFolderByName {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        namespace Responses {
            export type $200 = /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ Components.Schemas.BaseVirtualFolder;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetFolders {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ Components.Schemas.BaseVirtualFolder[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetFoldersQuotaScans {
        namespace Responses {
            export type $200 = Components.Schemas.FolderQuotaScan[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetFsEvents {
        namespace Parameters {
            export type Actions = Components.Schemas.FsEventAction[];
            export type Bucket = string;
            export type CsvExport = boolean;
            export type EndTimestamp = number; // int64
            export type Endpoint = string;
            export type FromId = string;
            export type FsProvider = /**
             * Filesystem providers:
             *   * `0` - Local filesystem
             *   * `1` - S3 Compatible Object Storage
             *   * `2` - Google Cloud Storage
             *   * `3` - Azure Blob Storage
             *   * `4` - Local filesystem encrypted
             *   * `5` - SFTP
             *   * `6` - HTTP filesystem
             *
             */
            Components.Schemas.FsProviders;
            export type InstanceIds = string[];
            export type Ip = string;
            export type Limit = number;
            /**
             * example:
             * DESC
             */
            export type Order = "ASC" | "DESC";
            export type Protocols = /**
             * Protocols:
             *   * `SSH` - SSH commands
             *   * `SFTP` - SFTP protocol
             *   * `SCP` - SCP protocol
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV
             *   * `HTTP` - WebClient/REST API
             *   * `HTTPShare` - the event is generated in a public share
             *   * `DataRetention` - the event is generated by a data retention check
             *   * `EventAction` - the event is generated by an EventManager action
             *   * `OIDC` - OpenID Connect
             *
             */
            Components.Schemas.EventProtocols[];
            export type Role = string;
            export type SshCmd = string;
            export type StartTimestamp = number; // int64
            export type Statuses = /**
             * Event status:
             *   * `1` - no error
             *   * `2` - generic error
             *   * `3` - quota exceeded error
             *
             */
            Components.Schemas.FsEventStatus[];
            export type Username = string;
        }
        export interface QueryParameters {
            start_timestamp?: Parameters.StartTimestamp /* int64 */;
            end_timestamp?: Parameters.EndTimestamp /* int64 */;
            actions?: Parameters.Actions;
            username?: Parameters.Username;
            ip?: Parameters.Ip;
            ssh_cmd?: Parameters.SshCmd;
            fs_provider?: Parameters.FsProvider;
            bucket?: Parameters.Bucket;
            endpoint?: Parameters.Endpoint;
            protocols?: Parameters.Protocols;
            statuses?: Parameters.Statuses;
            instance_ids?: Parameters.InstanceIds;
            from_id?: Parameters.FromId;
            role?: Parameters.Role;
            csv_export?: Parameters.CsvExport;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * DESC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.FsEvent[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetGroupByName {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Group;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetGroups {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Group[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetIpListByIpornet {
        namespace Responses {
            export type $200 = Components.Schemas.IPListEntry;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetIpListEntries {
        namespace Parameters {
            export type Filter = string;
            export type From = string;
            export type Limit = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            filter?: Parameters.Filter;
            from?: Parameters.From;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.IPListEntry[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetLogEvents {
        namespace Parameters {
            export type CsvExport = boolean;
            export type EndTimestamp = number; // int64
            export type Events = /**
             * Event status:
             *   * `1` - Login failed
             *   * `2` - Login failed non-existent user
             *   * `3` - No login tried
             *   * `4` - Algorithm negotiation failed
             *
             */
            Components.Schemas.LogEventType[];
            export type FromId = string;
            export type InstanceIds = string[];
            export type Ip = string;
            export type Limit = number;
            /**
             * example:
             * DESC
             */
            export type Order = "ASC" | "DESC";
            export type Protocols = /**
             * Protocols:
             *   * `SSH` - SSH commands
             *   * `SFTP` - SFTP protocol
             *   * `SCP` - SCP protocol
             *   * `FTP` - plain FTP and FTPES/FTPS
             *   * `DAV` - WebDAV
             *   * `HTTP` - WebClient/REST API
             *   * `HTTPShare` - the event is generated in a public share
             *   * `DataRetention` - the event is generated by a data retention check
             *   * `EventAction` - the event is generated by an EventManager action
             *   * `OIDC` - OpenID Connect
             *
             */
            Components.Schemas.EventProtocols[];
            export type Role = string;
            export type StartTimestamp = number; // int64
            export type Username = string;
        }
        export interface QueryParameters {
            start_timestamp?: Parameters.StartTimestamp /* int64 */;
            end_timestamp?: Parameters.EndTimestamp /* int64 */;
            events?: Parameters.Events;
            username?: Parameters.Username;
            ip?: Parameters.Ip;
            protocols?: Parameters.Protocols;
            instance_ids?: Parameters.InstanceIds;
            from_id?: Parameters.FromId;
            role?: Parameters.Role;
            csv_export?: Parameters.CsvExport;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * DESC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.LogEvent[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetProviderEvents {
        namespace Parameters {
            export type Actions = Components.Schemas.ProviderEventAction[];
            export type CsvExport = boolean;
            export type EndTimestamp = number; // int64
            export type FromId = string;
            export type InstanceIds = string[];
            export type Ip = string;
            export type Limit = number;
            export type ObjectName = string;
            export type ObjectTypes = Components.Schemas.ProviderEventObjectType[];
            export type OmitObjectData = boolean;
            /**
             * example:
             * DESC
             */
            export type Order = "ASC" | "DESC";
            export type Role = string;
            export type StartTimestamp = number; // int64
            export type Username = string;
        }
        export interface QueryParameters {
            start_timestamp?: Parameters.StartTimestamp /* int64 */;
            end_timestamp?: Parameters.EndTimestamp /* int64 */;
            actions?: Parameters.Actions;
            username?: Parameters.Username;
            ip?: Parameters.Ip;
            object_name?: Parameters.ObjectName;
            object_types?: Parameters.ObjectTypes;
            instance_ids?: Parameters.InstanceIds;
            from_id?: Parameters.FromId;
            role?: Parameters.Role;
            csv_export?: Parameters.CsvExport;
            omit_object_data?: Parameters.OmitObjectData;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * DESC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ProviderEvent[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetRoleByName {
        namespace Responses {
            export type $200 = Components.Schemas.Role;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetRoles {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Role[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetShare {
        namespace Parameters {
            export type Compress = boolean;
        }
        export interface QueryParameters {
            compress?: Parameters.Compress;
        }
        namespace Responses {
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetShareDirContents {
        namespace Parameters {
            export type Path = string;
        }
        export interface QueryParameters {
            path?: Parameters.Path;
        }
        namespace Responses {
            export type $200 = Components.Schemas.DirEntry[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetStatus {
        namespace Responses {
            export type $200 = Components.Schemas.ServicesStatus;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetToken {
        export interface HeaderParameters {
            "X-SFTPGO-OTP"?: Parameters.XSFTPGOOTP;
        }
        namespace Parameters {
            export type XSFTPGOOTP = string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Token;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserByUsername {
        namespace Parameters {
            export type ConfidentialData = number;
        }
        export interface QueryParameters {
            confidential_data?: Parameters.ConfidentialData;
        }
        namespace Responses {
            export type $200 = Components.Schemas.User;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserDirContents {
        namespace Parameters {
            export type Path = string;
        }
        export interface QueryParameters {
            path?: Parameters.Path;
        }
        namespace Responses {
            export type $200 = Components.Schemas.DirEntry[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserProfile {
        namespace Responses {
            export type $200 = Components.Schemas.UserProfile;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserRecoveryCodes {
        namespace Responses {
            export type $200 = /* Recovery codes to use if the user loses access to their second factor auth device. Each code can only be used once, you should use these codes to login and disable or reset 2FA for your account */ Components.Schemas.RecoveryCode[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserShareById {
        namespace Responses {
            export type $200 = Components.Schemas.Share;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserShares {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Share[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserToken {
        export interface HeaderParameters {
            "X-SFTPGO-OTP"?: Parameters.XSFTPGOOTP;
        }
        namespace Parameters {
            export type XSFTPGOOTP = string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.Token;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUserTotpConfigs {
        namespace Responses {
            export type $200 = Components.Schemas.TOTPConfig[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUsers {
        namespace Parameters {
            export type Limit = number;
            export type Offset = number;
            /**
             * example:
             * ASC
             */
            export type Order = "ASC" | "DESC";
        }
        export interface QueryParameters {
            offset?: Parameters.Offset;
            limit?: Parameters.Limit;
            order?: /**
             * example:
             * ASC
             */
            Parameters.Order;
        }
        namespace Responses {
            export type $200 = Components.Schemas.User[];
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUsersMetadataChecks {
        namespace Responses {
            export type $200 = Components.Schemas.MetadataCheck[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUsersQuotaScans {
        namespace Responses {
            export type $200 = Components.Schemas.QuotaScan[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetUsersRetentionChecks {
        namespace Responses {
            export type $200 = Components.Schemas.RetentionCheck[];
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace GetVersion {
        namespace Responses {
            export type $200 = Components.Schemas.VersionInfo;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Groups$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace Healthz {
        namespace Responses {
            /**
             * example:
             * ok
             */
            export type $200 = string;
        }
    }
    namespace Iplists$Type {
        namespace Parameters {
            export type Type = /**
             * IP List types:
             *   * `1` - allow list
             *   * `2` - defender
             *   * `3` - rate limiter safe list
             *
             */
            Components.Schemas.IPListType;
        }
        export interface PathParameters {
            type: Parameters.Type;
        }
    }
    namespace Iplists$Type$Ipornet {
        namespace Parameters {
            export type Ipornet = string;
            export type Type = /**
             * IP List types:
             *   * `1` - allow list
             *   * `2` - defender
             *   * `3` - rate limiter safe list
             *
             */
            Components.Schemas.IPListType;
        }
        export interface PathParameters {
            type: Parameters.Type;
            ipornet: Parameters.Ipornet;
        }
    }
    namespace Loaddata {
        namespace Parameters {
            export type Mode = 0 | 1 | 2;
            export type ScanQuota = 0 | 1 | 2;
        }
        export interface QueryParameters {
            "scan-quota"?: Parameters.ScanQuota;
            mode?: Parameters.Mode;
        }
    }
    namespace LoaddataFromFile {
        namespace Parameters {
            export type InputFile = string;
        }
        export interface QueryParameters {
            "input-file": Parameters.InputFile;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace LoaddataFromRequestBody {
        export type RequestBody = Components.Schemas.BackupData;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Logout {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace MetadataUsers$UsernameCheck {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace QuotasFolders$NameScan {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace QuotasFolders$NameUsage {
        namespace Parameters {
            /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            export type Mode = "add" | "reset";
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
        export interface QueryParameters {
            mode?: /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            Parameters.Mode;
        }
    }
    namespace QuotasUsers$UsernameScan {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace QuotasUsers$UsernameTransferUsage {
        namespace Parameters {
            /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            export type Mode = "add" | "reset";
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
        export interface QueryParameters {
            mode?: /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            Parameters.Mode;
        }
    }
    namespace QuotasUsers$UsernameUsage {
        namespace Parameters {
            /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            export type Mode = "add" | "reset";
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
        export interface QueryParameters {
            mode?: /**
             * Update type:
             *     * `add` - add the specified quota limits to the current used ones
             *     * `reset` - reset the values to the specified ones. This is the default
             *
             * example:
             * reset
             */
            Parameters.Mode;
        }
    }
    namespace RenameUserDir {
        namespace Parameters {
            export type Path = string;
            export type Target = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            target: Parameters.Target;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace RenameUserFile {
        namespace Parameters {
            export type Path = string;
            export type Target = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
            target: Parameters.Target;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace RetentionUsers$UsernameCheck {
        namespace Parameters {
            export type Notifications = /**
             * Options:
             *   * `Hook` - notify result using the defined hook. A "data_retention_hook" must be defined in your configuration file for this to work
             *   * `Email` - notify results by email. The admin starting the retention check must have an associated email address and the SMTP server must be configured for this to work
             *
             */
            Components.Schemas.RetentionCheckNotification[];
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
        export interface QueryParameters {
            notifications?: Parameters.Notifications;
        }
    }
    namespace Roles$Name {
        namespace Parameters {
            export type Name = string;
        }
        export interface PathParameters {
            name: Parameters.Name;
        }
    }
    namespace RunEventRule {
        namespace Responses {
            export type $202 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace SaveAdminTotpConfig {
        export type RequestBody = Components.Schemas.AdminTOTPConfig;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace SaveUserTotpConfig {
        export type RequestBody = Components.Schemas.UserTOTPConfig;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace SetpropsUserFile {
        namespace Parameters {
            export type Path = string;
        }
        export interface QueryParameters {
            path: Parameters.Path;
        }
        export interface RequestBody {
            /**
             * File modification time as unix timestamp in milliseconds
             */
            modification_time?: number;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $413 = Components.Responses.RequestEntityTooLarge;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Shares$Id {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace Shares$Id$FileName {
        export interface HeaderParameters {
            "X-SFTPGO-MTIME"?: Parameters.XSFTPGOMTIME;
        }
        namespace Parameters {
            export type FileName = string;
            export type Id = string;
            export type XSFTPGOMTIME = number;
        }
        export interface PathParameters {
            id: Parameters.Id;
            fileName: Parameters.FileName;
        }
    }
    namespace Shares$IdDirs {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace Shares$IdFiles {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace StartFolderQuotaScan {
        namespace Responses {
            export type $202 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace StartUserMetadataCheck {
        namespace Responses {
            export type $202 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace StartUserQuotaScan {
        namespace Responses {
            export type $202 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace StartUserRetentionCheck {
        export type RequestBody = Components.Schemas.FolderRetention[];
        namespace Responses {
            export type $202 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Streamzip {
        export type RequestBody = string[];
        namespace Responses {
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateAdmin {
        export type RequestBody = Components.Schemas.Admin;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateAdminProfile {
        export type RequestBody = Components.Schemas.AdminProfile;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateApiKey {
        export type RequestBody = Components.Schemas.APIKey;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateEventAction {
        export type RequestBody = Components.Schemas.BaseEventAction;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateEventRule {
        export type RequestBody = Components.Schemas.EventRuleMinimal;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateFolder {
        export type RequestBody = /* Defines the filesystem for the virtual folder and the used quota limits. The same folder can be shared among multiple users and each user can have different quota limits or a different virtual path. */ Components.Schemas.BaseVirtualFolder;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateGroup {
        export type RequestBody = Components.Schemas.Group;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateIpListEntry {
        export type RequestBody = Components.Schemas.IPListEntry;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateRole {
        export type RequestBody = Components.Schemas.Role;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateUser {
        namespace Parameters {
            export type Disconnect = 0 | 1;
        }
        export interface QueryParameters {
            disconnect?: Parameters.Disconnect;
        }
        export type RequestBody = Components.Schemas.User;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateUserProfile {
        export type RequestBody = Components.Schemas.UserProfile;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UpdateUserShare {
        export type RequestBody = Components.Schemas.Share;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UploadSingleToShare {
        export type RequestBody = string; // binary
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $413 = Components.Responses.RequestEntityTooLarge;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UploadToShare {
        export interface RequestBody {
            filenames?: [
                string,
                ...string[]
            ];
        }
        namespace Responses {
            export type $201 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $413 = Components.Responses.RequestEntityTooLarge;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UserFileActionsCopy {
        namespace Parameters {
            export type Path = string;
            export type Target = string;
        }
        namespace Post {
            namespace Responses {
                export type $200 = Components.Schemas.ApiResponse;
                export type $400 = Components.Responses.BadRequest;
                export type $401 = Components.Responses.Unauthorized;
                export type $403 = Components.Responses.Forbidden;
                export type $500 = Components.Responses.InternalServerError;
                export type Default = Components.Responses.DefaultResponse;
            }
        }
        export interface QueryParameters {
            path: Parameters.Path;
            target: Parameters.Target;
        }
    }
    namespace UserFileActionsMove {
        namespace Parameters {
            export type Path = string;
            export type Target = string;
        }
        namespace Post {
            namespace Responses {
                export type $200 = Components.Schemas.ApiResponse;
                export type $400 = Components.Responses.BadRequest;
                export type $401 = Components.Responses.Unauthorized;
                export type $403 = Components.Responses.Forbidden;
                export type $500 = Components.Responses.InternalServerError;
                export type Default = Components.Responses.DefaultResponse;
            }
        }
        export interface QueryParameters {
            path: Parameters.Path;
            target: Parameters.Target;
        }
    }
    namespace UserForgotPassword {
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UserQuotaUpdateUsage {
        export type RequestBody = Components.Schemas.QuotaUsage;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UserResetPassword {
        export interface RequestBody {
            code?: string;
            password?: string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace UserShares$Id {
        namespace Parameters {
            export type Id = string;
        }
        export interface PathParameters {
            id: Parameters.Id;
        }
    }
    namespace UserTransferQuotaUpdateUsage {
        export type RequestBody = Components.Schemas.TransferQuotaUsage;
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $404 = Components.Responses.NotFound;
            export type $409 = Components.Responses.Conflict;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace Users$Username {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Users$Username2faDisable {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Users$UsernameForgotPassword {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace Users$UsernameResetPassword {
        namespace Parameters {
            export type Username = string;
        }
        export interface PathParameters {
            username: Parameters.Username;
        }
    }
    namespace ValidateAdminTotpSecret {
        export interface RequestBody {
            /**
             * name of the configuration to use to validate the passcode
             */
            config_name?: string;
            /**
             * passcode to validate
             */
            passcode?: string;
            /**
             * secret to use to validate the passcode
             */
            secret?: string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
    namespace ValidateUserTotpSecret {
        export interface RequestBody {
            /**
             * name of the configuration to use to validate the passcode
             */
            config_name?: string;
            /**
             * passcode to validate
             */
            passcode?: string;
            /**
             * secret to use to validate the passcode
             */
            secret?: string;
        }
        namespace Responses {
            export type $200 = Components.Schemas.ApiResponse;
            export type $400 = Components.Responses.BadRequest;
            export type $401 = Components.Responses.Unauthorized;
            export type $403 = Components.Responses.Forbidden;
            export type $500 = Components.Responses.InternalServerError;
            export type Default = Components.Responses.DefaultResponse;
        }
    }
}

export interface OperationMethods {
  /**
   * healthz - health check
   * 
   * This endpoint can be used to check if the application is running and responding to requests
   */
  'healthz'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.Healthz.Responses.$200>
  /**
   * get_share - Download shared files and folders as a single zip file
   * 
   * A zip file, containing the shared files and folders, will be generated on the fly and returned as response body. Only folders and regular files will be included in the zip. The share must be defined with the read scope and the associated user must have list and download permissions
   */
  'get_share'(
    parameters?: Parameters<Paths.Shares$Id.PathParameters & Paths.GetShare.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<any>
  /**
   * upload_to_share - Upload one or more files to the shared path
   * 
   * The share must be defined with the write scope and the associated user must have the upload permission
   */
  'upload_to_share'(
    parameters?: Parameters<Paths.Shares$Id.PathParameters> | null,
    data?: Paths.UploadToShare.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UploadToShare.Responses.$201>
  /**
   * download_share_file - Download a single file
   * 
   * Returns the file contents as response body. The share must have exactly one path defined and it must be a directory for this to work
   */
  'download_share_file'(
    parameters?: Parameters<Paths.Shares$IdFiles.PathParameters & Paths.DownloadShareFile.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<any>
  /**
   * get_share_dir_contents - Read directory contents
   * 
   * Returns the contents of the specified directory for the specified share. The share must have exactly one path defined and it must be a directory for this to work
   */
  'get_share_dir_contents'(
    parameters?: Parameters<Paths.Shares$IdDirs.PathParameters & Paths.GetShareDirContents.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetShareDirContents.Responses.$200>
  /**
   * upload_single_to_share - Upload a single file to the shared path
   * 
   * The share must be defined with the write scope and the associated user must have the upload/overwrite permissions
   */
  'upload_single_to_share'(
    parameters?: Parameters<Paths.Shares$Id$FileName.PathParameters & Paths.Shares$Id$FileName.HeaderParameters> | null,
    data?: Paths.UploadSingleToShare.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UploadSingleToShare.Responses.$201>
  /**
   * get_token - Get a new admin access token
   * 
   * Returns an access token and its expiration
   */
  'get_token'(
    parameters?: Parameters<Paths.GetToken.HeaderParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetToken.Responses.$200>
  /**
   * logout - Invalidate an admin access token
   * 
   * Allows to invalidate an admin token before its expiration
   */
  'logout'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.Logout.Responses.$200>
  /**
   * get_user_token - Get a new user access token
   * 
   * Returns an access token and its expiration
   */
  'get_user_token'(
    parameters?: Parameters<Paths.GetUserToken.HeaderParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserToken.Responses.$200>
  /**
   * client_logout - Invalidate a user access token
   * 
   * Allows to invalidate a client token before its expiration
   */
  'client_logout'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.ClientLogout.Responses.$200>
  /**
   * get_version - Get version details
   * 
   * Returns version details such as the version number, build date, commit hash and enabled features
   */
  'get_version'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetVersion.Responses.$200>
  /**
   * change_admin_password - Change admin password
   * 
   * Changes the password for the logged in admin
   */
  'change_admin_password'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.ChangeAdminPassword.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.ChangeAdminPassword.Responses.$200>
  /**
   * get_admin_profile - Get admin profile
   * 
   * Returns the profile for the logged in admin
   */
  'get_admin_profile'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetAdminProfile.Responses.$200>
  /**
   * update_admin_profile - Update admin profile
   * 
   * Allows to update the profile for the logged in admin
   */
  'update_admin_profile'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.UpdateAdminProfile.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateAdminProfile.Responses.$200>
  /**
   * get_admin_recovery_codes - Get recovery codes
   * 
   * Returns the recovery codes for the logged in admin. Recovery codes can be used if the admin loses access to their second factor auth device. Recovery codes are returned unencrypted
   */
  'get_admin_recovery_codes'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetAdminRecoveryCodes.Responses.$200>
  /**
   * generate_admin_recovery_codes - Generate recovery codes
   * 
   * Generates new recovery codes for the logged in admin. Generating new recovery codes you automatically invalidate old ones
   */
  'generate_admin_recovery_codes'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GenerateAdminRecoveryCodes.Responses.$200>
  /**
   * get_admin_totp_configs - Get available TOTP configuration
   * 
   * Returns the available TOTP configurations for the logged in admin
   */
  'get_admin_totp_configs'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetAdminTotpConfigs.Responses.$200>
  /**
   * generate_admin_totp_secret - Generate a new TOTP secret
   * 
   * Generates a new TOTP secret, including the QR code as png, using the specified configuration for the logged in admin
   */
  'generate_admin_totp_secret'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.GenerateAdminTotpSecret.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GenerateAdminTotpSecret.Responses.$200>
  /**
   * validate_admin_totp_secret - Validate a one time authentication code
   * 
   * Checks if the given authentication code can be validated using the specified secret and config name
   */
  'validate_admin_totp_secret'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.ValidateAdminTotpSecret.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.ValidateAdminTotpSecret.Responses.$200>
  /**
   * save_admin_totp_config - Save a TOTP config
   * 
   * Saves the specified TOTP config for the logged in admin
   */
  'save_admin_totp_config'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.SaveAdminTotpConfig.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.SaveAdminTotpConfig.Responses.$200>
  /**
   * get_connections - Get connections details
   * 
   * Returns the active users and info about their current uploads/downloads
   */
  'get_connections'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetConnections.Responses.$200>
  /**
   * close_connection - Close connection
   * 
   * Terminates an active connection
   */
  'close_connection'(
    parameters?: Parameters<Paths.CloseConnection.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.CloseConnection.Responses.$200>
  /**
   * get_ip_list_entries - Get IP list entries
   * 
   * Returns an array with one or more IP list entry
   */
  'get_ip_list_entries'(
    parameters?: Parameters<Paths.Iplists$Type.PathParameters & Paths.GetIpListEntries.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetIpListEntries.Responses.$200>
  /**
   * add_ip_list_entry - Add a new IP list entry
   * 
   * Add an IP address or a CIDR network to a supported list
   */
  'add_ip_list_entry'(
    parameters?: Parameters<Paths.Iplists$Type.PathParameters> | null,
    data?: Paths.AddIpListEntry.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddIpListEntry.Responses.$201>
  /**
   * get_ip_list_by_ipornet - Find entry by ipornet
   * 
   * Returns the entry with the given ipornet if it exists.
   */
  'get_ip_list_by_ipornet'(
    parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetIpListByIpornet.Responses.$200>
  /**
   * update_ip_list_entry - Update IP list entry
   * 
   * Updates an existing IP list entry
   */
  'update_ip_list_entry'(
    parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
    data?: Paths.UpdateIpListEntry.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateIpListEntry.Responses.$200>
  /**
   * delete_ip_list_entry - Delete IP list entry
   * 
   * Deletes an existing IP list entry
   */
  'delete_ip_list_entry'(
    parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteIpListEntry.Responses.$200>
  /**
   * get_defender_hosts - Get hosts
   * 
   * Returns hosts that are banned or for which some violations have been detected
   */
  'get_defender_hosts'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetDefenderHosts.Responses.$200>
  /**
   * get_defender_host_by_id - Get host by id
   * 
   * Returns the host with the given id, if it exists
   */
  'get_defender_host_by_id'(
    parameters?: Parameters<Paths.DefenderHosts$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetDefenderHostById.Responses.$200>
  /**
   * delete_defender_host_by_id - Removes a host from the defender lists
   * 
   * Unbans the specified host or clears its violations
   */
  'delete_defender_host_by_id'(
    parameters?: Parameters<Paths.DefenderHosts$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteDefenderHostById.Responses.$200>
  /**
   * get_users_metadata_checks - Get metadata checks
   * 
   * Returns the active metadata checks
   */
  'get_users_metadata_checks'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUsersMetadataChecks.Responses.$200>
  /**
   * start_user_metadata_check - Start a metadata check
   * 
   * Starts a new metadata check for the given user. A metadata check requires a metadata plugin and removes the metadata associated to missing items (for example objects deleted outside SFTPGo). If a metadata check for this user is already active a 409 status code is returned. Metadata are stored for cloud storage backends. This API does nothing for other backends or if no metadata plugin is configured
   */
  'start_user_metadata_check'(
    parameters?: Parameters<Paths.MetadataUsers$UsernameCheck.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.StartUserMetadataCheck.Responses.$202>
  /**
   * get_users_retention_checks - Get retention checks
   * 
   * Returns the active retention checks
   */
  'get_users_retention_checks'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUsersRetentionChecks.Responses.$200>
  /**
   * start_user_retention_check - Start a retention check
   * 
   * Starts a new retention check for the given user. If a retention check for this user is already active a 409 status code is returned
   */
  'start_user_retention_check'(
    parameters?: Parameters<Paths.RetentionUsers$UsernameCheck.PathParameters & Paths.RetentionUsers$UsernameCheck.QueryParameters> | null,
    data?: Paths.StartUserRetentionCheck.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.StartUserRetentionCheck.Responses.$202>
  /**
   * get_users_quota_scans - Get active user quota scans
   * 
   * Returns the active user quota scans
   */
  'get_users_quota_scans'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUsersQuotaScans.Responses.$200>
  /**
   * start_user_quota_scan - Start a user quota scan
   * 
   * Starts a new quota scan for the given user. A quota scan updates the number of files and their total size for the specified user and the virtual folders, if any, included in his quota
   */
  'start_user_quota_scan'(
    parameters?: Parameters<Paths.QuotasUsers$UsernameScan.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.StartUserQuotaScan.Responses.$202>
  /**
   * user_quota_update_usage - Update disk quota usage limits
   * 
   * Sets the current used quota limits for the given user
   */
  'user_quota_update_usage'(
    parameters?: Parameters<Paths.QuotasUsers$UsernameUsage.PathParameters & Paths.QuotasUsers$UsernameUsage.QueryParameters> | null,
    data?: Paths.UserQuotaUpdateUsage.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UserQuotaUpdateUsage.Responses.$200>
  /**
   * user_transfer_quota_update_usage - Update transfer quota usage limits
   * 
   * Sets the current used transfer quota limits for the given user
   */
  'user_transfer_quota_update_usage'(
    parameters?: Parameters<Paths.QuotasUsers$UsernameTransferUsage.PathParameters & Paths.QuotasUsers$UsernameTransferUsage.QueryParameters> | null,
    data?: Paths.UserTransferQuotaUpdateUsage.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UserTransferQuotaUpdateUsage.Responses.$200>
  /**
   * get_folders_quota_scans - Get active folder quota scans
   * 
   * Returns the active folder quota scans
   */
  'get_folders_quota_scans'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetFoldersQuotaScans.Responses.$200>
  /**
   * start_folder_quota_scan - Start a folder quota scan
   * 
   * Starts a new quota scan for the given folder. A quota scan update the number of files and their total size for the specified folder
   */
  'start_folder_quota_scan'(
    parameters?: Parameters<Paths.QuotasFolders$NameScan.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.StartFolderQuotaScan.Responses.$202>
  /**
   * folder_quota_update_usage - Update folder quota usage limits
   * 
   * Sets the current used quota limits for the given folder
   */
  'folder_quota_update_usage'(
    parameters?: Parameters<Paths.QuotasFolders$NameUsage.PathParameters & Paths.FolderQuotaUpdateUsage.QueryParameters & Paths.QuotasFolders$NameUsage.QueryParameters> | null,
    data?: Paths.FolderQuotaUpdateUsage.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.FolderQuotaUpdateUsage.Responses.$200>
  /**
   * get_folders - Get folders
   * 
   * Returns an array with one or more folders
   */
  'get_folders'(
    parameters?: Parameters<Paths.GetFolders.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetFolders.Responses.$200>
  /**
   * add_folder - Add folder
   * 
   * Adds a new folder. A quota scan is required to update the used files/size
   */
  'add_folder'(
    parameters?: Parameters<Paths.AddFolder.QueryParameters> | null,
    data?: Paths.AddFolder.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddFolder.Responses.$201>
  /**
   * get_folder_by_name - Find folders by name
   * 
   * Returns the folder with the given name if it exists.
   */
  'get_folder_by_name'(
    parameters?: Parameters<Paths.Folders$Name.PathParameters & Paths.GetFolderByName.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetFolderByName.Responses.$200>
  /**
   * update_folder - Update folder
   * 
   * Updates an existing folder
   */
  'update_folder'(
    parameters?: Parameters<Paths.Folders$Name.PathParameters> | null,
    data?: Paths.UpdateFolder.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateFolder.Responses.$200>
  /**
   * delete_folder - Delete folder
   * 
   * Deletes an existing folder
   */
  'delete_folder'(
    parameters?: Parameters<Paths.Folders$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteFolder.Responses.$200>
  /**
   * get_groups - Get groups
   * 
   * Returns an array with one or more groups
   */
  'get_groups'(
    parameters?: Parameters<Paths.GetGroups.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetGroups.Responses.$200>
  /**
   * add_group - Add group
   * 
   * Adds a new group
   */
  'add_group'(
    parameters?: Parameters<Paths.AddGroup.QueryParameters> | null,
    data?: Paths.AddGroup.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddGroup.Responses.$201>
  /**
   * get_group_by_name - Find groups by name
   * 
   * Returns the group with the given name if it exists.
   */
  'get_group_by_name'(
    parameters?: Parameters<Paths.Groups$Name.PathParameters & Paths.GetGroupByName.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetGroupByName.Responses.$200>
  /**
   * update_group - Update group
   * 
   * Updates an existing group
   */
  'update_group'(
    parameters?: Parameters<Paths.Groups$Name.PathParameters> | null,
    data?: Paths.UpdateGroup.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateGroup.Responses.$200>
  /**
   * delete_group - Delete group
   * 
   * Deletes an existing group
   */
  'delete_group'(
    parameters?: Parameters<Paths.Groups$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteGroup.Responses.$200>
  /**
   * get_roles - Get roles
   * 
   * Returns an array with one or more roles
   */
  'get_roles'(
    parameters?: Parameters<Paths.GetRoles.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetRoles.Responses.$200>
  /**
   * add_role - Add role
   * 
   * Adds a new role
   */
  'add_role'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.AddRole.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddRole.Responses.$201>
  /**
   * get_role_by_name - Find roles by name
   * 
   * Returns the role with the given name if it exists.
   */
  'get_role_by_name'(
    parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetRoleByName.Responses.$200>
  /**
   * update_role - Update role
   * 
   * Updates an existing role
   */
  'update_role'(
    parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
    data?: Paths.UpdateRole.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateRole.Responses.$200>
  /**
   * delete_role - Delete role
   * 
   * Deletes an existing role
   */
  'delete_role'(
    parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteRole.Responses.$200>
  /**
   * get_event_actons - Get event actions
   * 
   * Returns an array with one or more event actions
   */
  'get_event_actons'(
    parameters?: Parameters<Paths.GetEventActons.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetEventActons.Responses.$200>
  /**
   * add_event_action - Add event action
   * 
   * Adds a new event actions
   */
  'add_event_action'(
    parameters?: Parameters<Paths.AddEventAction.QueryParameters> | null,
    data?: Paths.AddEventAction.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddEventAction.Responses.$201>
  /**
   * get_event_action_by_name - Find event actions by name
   * 
   * Returns the event action with the given name if it exists.
   */
  'get_event_action_by_name'(
    parameters?: Parameters<Paths.Eventactions$Name.PathParameters & Paths.GetEventActionByName.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetEventActionByName.Responses.$200>
  /**
   * update_event_action - Update event action
   * 
   * Updates an existing event action
   */
  'update_event_action'(
    parameters?: Parameters<Paths.Eventactions$Name.PathParameters> | null,
    data?: Paths.UpdateEventAction.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateEventAction.Responses.$200>
  /**
   * delete_event_action - Delete event action
   * 
   * Deletes an existing event action
   */
  'delete_event_action'(
    parameters?: Parameters<Paths.Eventactions$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteEventAction.Responses.$200>
  /**
   * get_event_rules - Get event rules
   * 
   * Returns an array with one or more event rules
   */
  'get_event_rules'(
    parameters?: Parameters<Paths.GetEventRules.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetEventRules.Responses.$200>
  /**
   * add_event_rule - Add event rule
   * 
   * Adds a new event rule
   */
  'add_event_rule'(
    parameters?: Parameters<Paths.AddEventRule.QueryParameters> | null,
    data?: Paths.AddEventRule.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddEventRule.Responses.$201>
  /**
   * get_event_rile_by_name - Find event rules by name
   * 
   * Returns the event rule with the given name if it exists.
   */
  'get_event_rile_by_name'(
    parameters?: Parameters<Paths.Eventrules$Name.PathParameters & Paths.GetEventRileByName.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetEventRileByName.Responses.$200>
  /**
   * update_event_rule - Update event rule
   * 
   * Updates an existing event rule
   */
  'update_event_rule'(
    parameters?: Parameters<Paths.Eventrules$Name.PathParameters> | null,
    data?: Paths.UpdateEventRule.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateEventRule.Responses.$200>
  /**
   * delete_event_rule - Delete event rule
   * 
   * Deletes an existing event rule
   */
  'delete_event_rule'(
    parameters?: Parameters<Paths.Eventrules$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteEventRule.Responses.$200>
  /**
   * run_event_rule - Run an on-demand event rule
   * 
   * The rule's actions will run in background. SFTPGo will not monitor any concurrency and such. If you want to be notified at the end of the execution please add an appropriate action
   */
  'run_event_rule'(
    parameters?: Parameters<Paths.EventrulesRun$Name.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.RunEventRule.Responses.$202>
  /**
   * get_fs_events - Get filesystem events
   * 
   * Returns an array with one or more filesystem events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
   */
  'get_fs_events'(
    parameters?: Parameters<Paths.GetFsEvents.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetFsEvents.Responses.$200>
  /**
   * get_provider_events - Get provider events
   * 
   * Returns an array with one or more provider events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
   */
  'get_provider_events'(
    parameters?: Parameters<Paths.GetProviderEvents.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetProviderEvents.Responses.$200>
  /**
   * get_log_events - Get log events
   * 
   * Returns an array with one or more log events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
   */
  'get_log_events'(
    parameters?: Parameters<Paths.GetLogEvents.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetLogEvents.Responses.$200>
  /**
   * get_api_keys - Get API keys
   * 
   * Returns an array with one or more API keys. For security reasons hashed keys are omitted in the response
   */
  'get_api_keys'(
    parameters?: Parameters<Paths.GetApiKeys.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetApiKeys.Responses.$200>
  /**
   * add_api_key - Add API key
   * 
   * Adds a new API key
   */
  'add_api_key'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.AddApiKey.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddApiKey.Responses.$201>
  /**
   * get_api_key_by_id - Find API key by id
   * 
   * Returns the API key with the given id, if it exists. For security reasons the hashed key is omitted in the response
   */
  'get_api_key_by_id'(
    parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetApiKeyById.Responses.$200>
  /**
   * update_api_key - Update API key
   * 
   * Updates an existing API key. You cannot update the key itself, the creation date and the last use
   */
  'update_api_key'(
    parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
    data?: Paths.UpdateApiKey.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateApiKey.Responses.$200>
  /**
   * delete_api_key - Delete API key
   * 
   * Deletes an existing API key
   */
  'delete_api_key'(
    parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteApiKey.Responses.$200>
  /**
   * get_admins - Get admins
   * 
   * Returns an array with one or more admins. For security reasons hashed passwords are omitted in the response
   */
  'get_admins'(
    parameters?: Parameters<Paths.GetAdmins.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetAdmins.Responses.$200>
  /**
   * add_admin - Add admin
   * 
   * Adds a new admin. Recovery codes and TOTP configuration cannot be set using this API: each admin must use the specific APIs
   */
  'add_admin'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.AddAdmin.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddAdmin.Responses.$201>
  /**
   * get_admin_by_username - Find admins by username
   * 
   * Returns the admin with the given username, if it exists. For security reasons the hashed password is omitted in the response
   */
  'get_admin_by_username'(
    parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetAdminByUsername.Responses.$200>
  /**
   * update_admin - Update admin
   * 
   * Updates an existing admin. Recovery codes and TOTP configuration cannot be set/updated using this API: each admin must use the specific APIs. You are not allowed to update the admin impersonated using an API key
   */
  'update_admin'(
    parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
    data?: Paths.UpdateAdmin.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateAdmin.Responses.$200>
  /**
   * delete_admin - Delete admin
   * 
   * Deletes an existing admin
   */
  'delete_admin'(
    parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteAdmin.Responses.$200>
  /**
   * disable_admin_2fa - Disable second factor authentication
   * 
   * Disables second factor authentication for the given admin. This API must be used if the admin loses access to their second factor auth device and has no recovery codes
   */
  'disable_admin_2fa'(
    parameters?: Parameters<Paths.Admins$Username2faDisable.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DisableAdmin2fa.Responses.$200>
  /**
   * admin_forgot_password - Send a password reset code by email
   * 
   * You must set up an SMTP server and the account must have a valid email address, in which case SFTPGo will send a code via email to reset the password. If the specified admin does not exist, the request will be silently ignored (a success response will be returned) to avoid disclosing existing admins
   */
  'admin_forgot_password'(
    parameters?: Parameters<Paths.Admins$UsernameForgotPassword.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AdminForgotPassword.Responses.$200>
  /**
   * admin_reset_password - Reset the password
   * 
   * Set a new password using the code received via email
   */
  'admin_reset_password'(
    parameters?: Parameters<Paths.Admins$UsernameResetPassword.PathParameters> | null,
    data?: Paths.AdminResetPassword.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AdminResetPassword.Responses.$200>
  /**
   * get_users - Get users
   * 
   * Returns an array with one or more users. For security reasons hashed passwords are omitted in the response
   */
  'get_users'(
    parameters?: Parameters<Paths.GetUsers.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUsers.Responses.$200>
  /**
   * add_user - Add user
   * 
   * Adds a new user.Recovery codes and TOTP configuration cannot be set using this API: each user must use the specific APIs
   */
  'add_user'(
    parameters?: Parameters<Paths.AddUser.QueryParameters> | null,
    data?: Paths.AddUser.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddUser.Responses.$201>
  /**
   * get_user_by_username - Find users by username
   * 
   * Returns the user with the given username if it exists. For security reasons the hashed password is omitted in the response
   */
  'get_user_by_username'(
    parameters?: Parameters<Paths.Users$Username.PathParameters & Paths.GetUserByUsername.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserByUsername.Responses.$200>
  /**
   * update_user - Update user
   * 
   * Updates an existing user and optionally disconnects it, if connected, to apply the new settings. The current password will be preserved if the password field is omitted in the request body. Recovery codes and TOTP configuration cannot be set/updated using this API: each user must use the specific APIs
   */
  'update_user'(
    parameters?: Parameters<Paths.Users$Username.PathParameters & Paths.UpdateUser.QueryParameters> | null,
    data?: Paths.UpdateUser.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateUser.Responses.$200>
  /**
   * delete_user - Delete user
   * 
   * Deletes an existing user
   */
  'delete_user'(
    parameters?: Parameters<Paths.Users$Username.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteUser.Responses.$200>
  /**
   * disable_user_2fa - Disable second factor authentication
   * 
   * Disables second factor authentication for the given user. This API must be used if the user loses access to their second factor auth device and has no recovery codes
   */
  'disable_user_2fa'(
    parameters?: Parameters<Paths.Users$Username2faDisable.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DisableUser2fa.Responses.$200>
  /**
   * user_forgot_password - Send a password reset code by email
   * 
   * You must configure an SMTP server, the account must have a valid email address and must not have the "reset-password-disabled" restriction, in which case SFTPGo will send a code via email to reset the password. If the specified user does not exist, the request will be silently ignored (a success response will be returned) to avoid disclosing existing users
   */
  'user_forgot_password'(
    parameters?: Parameters<Paths.Users$UsernameForgotPassword.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UserForgotPassword.Responses.$200>
  /**
   * user_reset_password - Reset the password
   * 
   * Set a new password using the code received via email
   */
  'user_reset_password'(
    parameters?: Parameters<Paths.Users$UsernameResetPassword.PathParameters> | null,
    data?: Paths.UserResetPassword.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UserResetPassword.Responses.$200>
  /**
   * get_status - Get status
   * 
   * Retrieves the status of the active services
   */
  'get_status'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetStatus.Responses.$200>
  /**
   * dumpdata - Dump data
   * 
   * Backups data as data provider independent JSON. The backup can be saved in a local file on the server, to avoid exposing sensitive data over the network, or returned as response body. The output of dumpdata can be used as input for loaddata
   */
  'dumpdata'(
    parameters?: Parameters<Paths.Dumpdata.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.Dumpdata.Responses.$200>
  /**
   * loaddata_from_file - Load data from path
   * 
   * Restores SFTPGo data from a JSON backup file on the server. Objects will be restored one by one and the restore is stopped if a object cannot be added or updated, so it could happen a partial restore
   */
  'loaddata_from_file'(
    parameters?: Parameters<Paths.LoaddataFromFile.QueryParameters & Paths.Loaddata.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.LoaddataFromFile.Responses.$200>
  /**
   * loaddata_from_request_body - Load data
   * 
   * Restores SFTPGo data from a JSON backup. Objects will be restored one by one and the restore is stopped if a object cannot be added or updated, so it could happen a partial restore
   */
  'loaddata_from_request_body'(
    parameters?: Parameters<Paths.Loaddata.QueryParameters> | null,
    data?: Paths.LoaddataFromRequestBody.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.LoaddataFromRequestBody.Responses.$200>
  /**
   * change_user_password - Change user password
   * 
   * Changes the password for the logged in user
   */
  'change_user_password'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.ChangeUserPassword.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.ChangeUserPassword.Responses.$200>
  /**
   * get_user_profile - Get user profile
   * 
   * Returns the profile for the logged in user
   */
  'get_user_profile'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserProfile.Responses.$200>
  /**
   * update_user_profile - Update user profile
   * 
   * Allows to update the profile for the logged in user
   */
  'update_user_profile'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.UpdateUserProfile.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateUserProfile.Responses.$200>
  /**
   * get_user_recovery_codes - Get recovery codes
   * 
   * Returns the recovery codes for the logged in user. Recovery codes can be used if the user loses access to their second factor auth device. Recovery codes are returned unencrypted
   */
  'get_user_recovery_codes'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserRecoveryCodes.Responses.$200>
  /**
   * generate_user_recovery_codes - Generate recovery codes
   * 
   * Generates new recovery codes for the logged in user. Generating new recovery codes you automatically invalidate old ones
   */
  'generate_user_recovery_codes'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GenerateUserRecoveryCodes.Responses.$200>
  /**
   * get_user_totp_configs - Get available TOTP configuration
   * 
   * Returns the available TOTP configurations for the logged in user
   */
  'get_user_totp_configs'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserTotpConfigs.Responses.$200>
  /**
   * generate_user_totp_secret - Generate a new TOTP secret
   * 
   * Generates a new TOTP secret, including the QR code as png, using the specified configuration for the logged in user
   */
  'generate_user_totp_secret'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.GenerateUserTotpSecret.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GenerateUserTotpSecret.Responses.$200>
  /**
   * validate_user_totp_secret - Validate a one time authentication code
   * 
   * Checks if the given authentication code can be validated using the specified secret and config name
   */
  'validate_user_totp_secret'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.ValidateUserTotpSecret.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.ValidateUserTotpSecret.Responses.$200>
  /**
   * save_user_totp_config - Save a TOTP config
   * 
   * Saves the specified TOTP config for the logged in user
   */
  'save_user_totp_config'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.SaveUserTotpConfig.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.SaveUserTotpConfig.Responses.$200>
  /**
   * get_user_shares - List user shares
   * 
   * Returns the share for the logged in user
   */
  'get_user_shares'(
    parameters?: Parameters<Paths.GetUserShares.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserShares.Responses.$200>
  /**
   * add_share - Add a share
   * 
   * Adds a new share. The share id will be auto-generated
   */
  'add_share'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.AddShare.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.AddShare.Responses.$201>
  /**
   * get_user_share_by_id - Get share by id
   * 
   * Returns a share by id for the logged in user
   */
  'get_user_share_by_id'(
    parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserShareById.Responses.$200>
  /**
   * update_user_share - Update share
   * 
   * Updates an existing share belonging to the logged in user
   */
  'update_user_share'(
    parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
    data?: Paths.UpdateUserShare.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.UpdateUserShare.Responses.$200>
  /**
   * delete_user_share - Delete share
   * 
   * Deletes an existing share belonging to the logged in user
   */
  'delete_user_share'(
    parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteUserShare.Responses.$200>
  /**
   * get_user_dir_contents - Read directory contents
   * 
   * Returns the contents of the specified directory for the logged in user
   */
  'get_user_dir_contents'(
    parameters?: Parameters<Paths.GetUserDirContents.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.GetUserDirContents.Responses.$200>
  /**
   * create_user_dir - Create a directory
   * 
   * Create a directory for the logged in user
   */
  'create_user_dir'(
    parameters?: Parameters<Paths.CreateUserDir.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.CreateUserDir.Responses.$201>
  /**
   * rename_user_dir - Rename a directory. Deprecated, use "file-actions/move"
   * 
   * Rename a directory for the logged in user. The rename is allowed for empty directory or for non empty local directories, with no virtual folders inside
   */
  'rename_user_dir'(
    parameters?: Parameters<Paths.RenameUserDir.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.RenameUserDir.Responses.$200>
  /**
   * delete_user_dir - Delete a directory
   * 
   * Delete a directory and any children it contains for the logged in user
   */
  'delete_user_dir'(
    parameters?: Parameters<Paths.DeleteUserDir.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteUserDir.Responses.$200>
  /**
   * download_user_file - Download a single file
   * 
   * Returns the file contents as response body
   */
  'download_user_file'(
    parameters?: Parameters<Paths.DownloadUserFile.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<any>
  /**
   * create_user_files - Upload files
   * 
   * Upload one or more files for the logged in user
   */
  'create_user_files'(
    parameters?: Parameters<Paths.CreateUserFiles.QueryParameters> | null,
    data?: Paths.CreateUserFiles.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.CreateUserFiles.Responses.$201>
  /**
   * rename_user_file - Rename a file
   * 
   * Rename a file for the logged in user. Deprecated, use "file-actions/move"
   */
  'rename_user_file'(
    parameters?: Parameters<Paths.RenameUserFile.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.RenameUserFile.Responses.$200>
  /**
   * delete_user_file - Delete a file
   * 
   * Delete a file for the logged in user.
   */
  'delete_user_file'(
    parameters?: Parameters<Paths.DeleteUserFile.QueryParameters> | null,
    data?: any,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.DeleteUserFile.Responses.$200>
  /**
   * create_user_file - Upload a single file
   * 
   * Upload a single file for the logged in user to an existing directory. This API does not use multipart/form-data and so no temporary files are created server side but only a single file can be uploaded as POST body
   */
  'create_user_file'(
    parameters?: Parameters<Paths.CreateUserFile.QueryParameters & Paths.CreateUserFile.HeaderParameters> | null,
    data?: Paths.CreateUserFile.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.CreateUserFile.Responses.$201>
  /**
   * setprops_user_file - Set metadata for a file/directory
   * 
   * Set supported metadata attributes for the specified file or directory
   */
  'setprops_user_file'(
    parameters?: Parameters<Paths.SetpropsUserFile.QueryParameters> | null,
    data?: Paths.SetpropsUserFile.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<Paths.SetpropsUserFile.Responses.$200>
  /**
   * streamzip - Download multiple files and folders as a single zip file
   * 
   * A zip file, containing the specified files and folders, will be generated on the fly and returned as response body. Only folders and regular files will be included in the zip
   */
  'streamzip'(
    parameters?: Parameters<UnknownParamsObject> | null,
    data?: Paths.Streamzip.RequestBody,
    config?: AxiosRequestConfig  
  ): OperationResponse<any>
}

export interface PathsDictionary {
  ['/healthz']: {
    /**
     * healthz - health check
     * 
     * This endpoint can be used to check if the application is running and responding to requests
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.Healthz.Responses.$200>
  }
  ['/shares/{id}']: {
    /**
     * get_share - Download shared files and folders as a single zip file
     * 
     * A zip file, containing the shared files and folders, will be generated on the fly and returned as response body. Only folders and regular files will be included in the zip. The share must be defined with the read scope and the associated user must have list and download permissions
     */
    'get'(
      parameters?: Parameters<Paths.Shares$Id.PathParameters & Paths.GetShare.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<any>
    /**
     * upload_to_share - Upload one or more files to the shared path
     * 
     * The share must be defined with the write scope and the associated user must have the upload permission
     */
    'post'(
      parameters?: Parameters<Paths.Shares$Id.PathParameters> | null,
      data?: Paths.UploadToShare.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UploadToShare.Responses.$201>
  }
  ['/shares/{id}/files']: {
    /**
     * download_share_file - Download a single file
     * 
     * Returns the file contents as response body. The share must have exactly one path defined and it must be a directory for this to work
     */
    'get'(
      parameters?: Parameters<Paths.Shares$IdFiles.PathParameters & Paths.DownloadShareFile.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<any>
  }
  ['/shares/{id}/dirs']: {
    /**
     * get_share_dir_contents - Read directory contents
     * 
     * Returns the contents of the specified directory for the specified share. The share must have exactly one path defined and it must be a directory for this to work
     */
    'get'(
      parameters?: Parameters<Paths.Shares$IdDirs.PathParameters & Paths.GetShareDirContents.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetShareDirContents.Responses.$200>
  }
  ['/shares/{id}/{fileName}']: {
    /**
     * upload_single_to_share - Upload a single file to the shared path
     * 
     * The share must be defined with the write scope and the associated user must have the upload/overwrite permissions
     */
    'post'(
      parameters?: Parameters<Paths.Shares$Id$FileName.PathParameters & Paths.Shares$Id$FileName.HeaderParameters> | null,
      data?: Paths.UploadSingleToShare.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UploadSingleToShare.Responses.$201>
  }
  ['/token']: {
    /**
     * get_token - Get a new admin access token
     * 
     * Returns an access token and its expiration
     */
    'get'(
      parameters?: Parameters<Paths.GetToken.HeaderParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetToken.Responses.$200>
  }
  ['/logout']: {
    /**
     * logout - Invalidate an admin access token
     * 
     * Allows to invalidate an admin token before its expiration
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.Logout.Responses.$200>
  }
  ['/user/token']: {
    /**
     * get_user_token - Get a new user access token
     * 
     * Returns an access token and its expiration
     */
    'get'(
      parameters?: Parameters<Paths.GetUserToken.HeaderParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserToken.Responses.$200>
  }
  ['/user/logout']: {
    /**
     * client_logout - Invalidate a user access token
     * 
     * Allows to invalidate a client token before its expiration
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.ClientLogout.Responses.$200>
  }
  ['/version']: {
    /**
     * get_version - Get version details
     * 
     * Returns version details such as the version number, build date, commit hash and enabled features
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetVersion.Responses.$200>
  }
  ['/admin/changepwd']: {
    /**
     * change_admin_password - Change admin password
     * 
     * Changes the password for the logged in admin
     */
    'put'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.ChangeAdminPassword.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.ChangeAdminPassword.Responses.$200>
  }
  ['/admin/profile']: {
    /**
     * get_admin_profile - Get admin profile
     * 
     * Returns the profile for the logged in admin
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetAdminProfile.Responses.$200>
    /**
     * update_admin_profile - Update admin profile
     * 
     * Allows to update the profile for the logged in admin
     */
    'put'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.UpdateAdminProfile.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateAdminProfile.Responses.$200>
  }
  ['/admin/2fa/recoverycodes']: {
    /**
     * get_admin_recovery_codes - Get recovery codes
     * 
     * Returns the recovery codes for the logged in admin. Recovery codes can be used if the admin loses access to their second factor auth device. Recovery codes are returned unencrypted
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetAdminRecoveryCodes.Responses.$200>
    /**
     * generate_admin_recovery_codes - Generate recovery codes
     * 
     * Generates new recovery codes for the logged in admin. Generating new recovery codes you automatically invalidate old ones
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GenerateAdminRecoveryCodes.Responses.$200>
  }
  ['/admin/totp/configs']: {
    /**
     * get_admin_totp_configs - Get available TOTP configuration
     * 
     * Returns the available TOTP configurations for the logged in admin
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetAdminTotpConfigs.Responses.$200>
  }
  ['/admin/totp/generate']: {
    /**
     * generate_admin_totp_secret - Generate a new TOTP secret
     * 
     * Generates a new TOTP secret, including the QR code as png, using the specified configuration for the logged in admin
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.GenerateAdminTotpSecret.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GenerateAdminTotpSecret.Responses.$200>
  }
  ['/admin/totp/validate']: {
    /**
     * validate_admin_totp_secret - Validate a one time authentication code
     * 
     * Checks if the given authentication code can be validated using the specified secret and config name
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.ValidateAdminTotpSecret.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.ValidateAdminTotpSecret.Responses.$200>
  }
  ['/admin/totp/save']: {
    /**
     * save_admin_totp_config - Save a TOTP config
     * 
     * Saves the specified TOTP config for the logged in admin
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.SaveAdminTotpConfig.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.SaveAdminTotpConfig.Responses.$200>
  }
  ['/connections']: {
    /**
     * get_connections - Get connections details
     * 
     * Returns the active users and info about their current uploads/downloads
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetConnections.Responses.$200>
  }
  ['/connections/{connectionID}']: {
    /**
     * close_connection - Close connection
     * 
     * Terminates an active connection
     */
    'delete'(
      parameters?: Parameters<Paths.CloseConnection.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.CloseConnection.Responses.$200>
  }
  ['/iplists/{type}']: {
    /**
     * get_ip_list_entries - Get IP list entries
     * 
     * Returns an array with one or more IP list entry
     */
    'get'(
      parameters?: Parameters<Paths.Iplists$Type.PathParameters & Paths.GetIpListEntries.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetIpListEntries.Responses.$200>
    /**
     * add_ip_list_entry - Add a new IP list entry
     * 
     * Add an IP address or a CIDR network to a supported list
     */
    'post'(
      parameters?: Parameters<Paths.Iplists$Type.PathParameters> | null,
      data?: Paths.AddIpListEntry.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddIpListEntry.Responses.$201>
  }
  ['/iplists/{type}/{ipornet}']: {
    /**
     * get_ip_list_by_ipornet - Find entry by ipornet
     * 
     * Returns the entry with the given ipornet if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetIpListByIpornet.Responses.$200>
    /**
     * update_ip_list_entry - Update IP list entry
     * 
     * Updates an existing IP list entry
     */
    'put'(
      parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
      data?: Paths.UpdateIpListEntry.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateIpListEntry.Responses.$200>
    /**
     * delete_ip_list_entry - Delete IP list entry
     * 
     * Deletes an existing IP list entry
     */
    'delete'(
      parameters?: Parameters<Paths.Iplists$Type$Ipornet.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteIpListEntry.Responses.$200>
  }
  ['/defender/hosts']: {
    /**
     * get_defender_hosts - Get hosts
     * 
     * Returns hosts that are banned or for which some violations have been detected
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetDefenderHosts.Responses.$200>
  }
  ['/defender/hosts/{id}']: {
    /**
     * get_defender_host_by_id - Get host by id
     * 
     * Returns the host with the given id, if it exists
     */
    'get'(
      parameters?: Parameters<Paths.DefenderHosts$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetDefenderHostById.Responses.$200>
    /**
     * delete_defender_host_by_id - Removes a host from the defender lists
     * 
     * Unbans the specified host or clears its violations
     */
    'delete'(
      parameters?: Parameters<Paths.DefenderHosts$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteDefenderHostById.Responses.$200>
  }
  ['/metadata/users/checks']: {
    /**
     * get_users_metadata_checks - Get metadata checks
     * 
     * Returns the active metadata checks
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUsersMetadataChecks.Responses.$200>
  }
  ['/metadata/users/{username}/check']: {
    /**
     * start_user_metadata_check - Start a metadata check
     * 
     * Starts a new metadata check for the given user. A metadata check requires a metadata plugin and removes the metadata associated to missing items (for example objects deleted outside SFTPGo). If a metadata check for this user is already active a 409 status code is returned. Metadata are stored for cloud storage backends. This API does nothing for other backends or if no metadata plugin is configured
     */
    'post'(
      parameters?: Parameters<Paths.MetadataUsers$UsernameCheck.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.StartUserMetadataCheck.Responses.$202>
  }
  ['/retention/users/checks']: {
    /**
     * get_users_retention_checks - Get retention checks
     * 
     * Returns the active retention checks
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUsersRetentionChecks.Responses.$200>
  }
  ['/retention/users/{username}/check']: {
    /**
     * start_user_retention_check - Start a retention check
     * 
     * Starts a new retention check for the given user. If a retention check for this user is already active a 409 status code is returned
     */
    'post'(
      parameters?: Parameters<Paths.RetentionUsers$UsernameCheck.PathParameters & Paths.RetentionUsers$UsernameCheck.QueryParameters> | null,
      data?: Paths.StartUserRetentionCheck.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.StartUserRetentionCheck.Responses.$202>
  }
  ['/quotas/users/scans']: {
    /**
     * get_users_quota_scans - Get active user quota scans
     * 
     * Returns the active user quota scans
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUsersQuotaScans.Responses.$200>
  }
  ['/quotas/users/{username}/scan']: {
    /**
     * start_user_quota_scan - Start a user quota scan
     * 
     * Starts a new quota scan for the given user. A quota scan updates the number of files and their total size for the specified user and the virtual folders, if any, included in his quota
     */
    'post'(
      parameters?: Parameters<Paths.QuotasUsers$UsernameScan.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.StartUserQuotaScan.Responses.$202>
  }
  ['/quotas/users/{username}/usage']: {
    /**
     * user_quota_update_usage - Update disk quota usage limits
     * 
     * Sets the current used quota limits for the given user
     */
    'put'(
      parameters?: Parameters<Paths.QuotasUsers$UsernameUsage.PathParameters & Paths.QuotasUsers$UsernameUsage.QueryParameters> | null,
      data?: Paths.UserQuotaUpdateUsage.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UserQuotaUpdateUsage.Responses.$200>
  }
  ['/quotas/users/{username}/transfer-usage']: {
    /**
     * user_transfer_quota_update_usage - Update transfer quota usage limits
     * 
     * Sets the current used transfer quota limits for the given user
     */
    'put'(
      parameters?: Parameters<Paths.QuotasUsers$UsernameTransferUsage.PathParameters & Paths.QuotasUsers$UsernameTransferUsage.QueryParameters> | null,
      data?: Paths.UserTransferQuotaUpdateUsage.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UserTransferQuotaUpdateUsage.Responses.$200>
  }
  ['/quotas/folders/scans']: {
    /**
     * get_folders_quota_scans - Get active folder quota scans
     * 
     * Returns the active folder quota scans
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetFoldersQuotaScans.Responses.$200>
  }
  ['/quotas/folders/{name}/scan']: {
    /**
     * start_folder_quota_scan - Start a folder quota scan
     * 
     * Starts a new quota scan for the given folder. A quota scan update the number of files and their total size for the specified folder
     */
    'post'(
      parameters?: Parameters<Paths.QuotasFolders$NameScan.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.StartFolderQuotaScan.Responses.$202>
  }
  ['/quotas/folders/{name}/usage']: {
    /**
     * folder_quota_update_usage - Update folder quota usage limits
     * 
     * Sets the current used quota limits for the given folder
     */
    'put'(
      parameters?: Parameters<Paths.QuotasFolders$NameUsage.PathParameters & Paths.FolderQuotaUpdateUsage.QueryParameters & Paths.QuotasFolders$NameUsage.QueryParameters> | null,
      data?: Paths.FolderQuotaUpdateUsage.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.FolderQuotaUpdateUsage.Responses.$200>
  }
  ['/folders']: {
    /**
     * get_folders - Get folders
     * 
     * Returns an array with one or more folders
     */
    'get'(
      parameters?: Parameters<Paths.GetFolders.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetFolders.Responses.$200>
    /**
     * add_folder - Add folder
     * 
     * Adds a new folder. A quota scan is required to update the used files/size
     */
    'post'(
      parameters?: Parameters<Paths.AddFolder.QueryParameters> | null,
      data?: Paths.AddFolder.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddFolder.Responses.$201>
  }
  ['/folders/{name}']: {
    /**
     * get_folder_by_name - Find folders by name
     * 
     * Returns the folder with the given name if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Folders$Name.PathParameters & Paths.GetFolderByName.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetFolderByName.Responses.$200>
    /**
     * update_folder - Update folder
     * 
     * Updates an existing folder
     */
    'put'(
      parameters?: Parameters<Paths.Folders$Name.PathParameters> | null,
      data?: Paths.UpdateFolder.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateFolder.Responses.$200>
    /**
     * delete_folder - Delete folder
     * 
     * Deletes an existing folder
     */
    'delete'(
      parameters?: Parameters<Paths.Folders$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteFolder.Responses.$200>
  }
  ['/groups']: {
    /**
     * get_groups - Get groups
     * 
     * Returns an array with one or more groups
     */
    'get'(
      parameters?: Parameters<Paths.GetGroups.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetGroups.Responses.$200>
    /**
     * add_group - Add group
     * 
     * Adds a new group
     */
    'post'(
      parameters?: Parameters<Paths.AddGroup.QueryParameters> | null,
      data?: Paths.AddGroup.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddGroup.Responses.$201>
  }
  ['/groups/{name}']: {
    /**
     * get_group_by_name - Find groups by name
     * 
     * Returns the group with the given name if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Groups$Name.PathParameters & Paths.GetGroupByName.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetGroupByName.Responses.$200>
    /**
     * update_group - Update group
     * 
     * Updates an existing group
     */
    'put'(
      parameters?: Parameters<Paths.Groups$Name.PathParameters> | null,
      data?: Paths.UpdateGroup.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateGroup.Responses.$200>
    /**
     * delete_group - Delete group
     * 
     * Deletes an existing group
     */
    'delete'(
      parameters?: Parameters<Paths.Groups$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteGroup.Responses.$200>
  }
  ['/roles']: {
    /**
     * get_roles - Get roles
     * 
     * Returns an array with one or more roles
     */
    'get'(
      parameters?: Parameters<Paths.GetRoles.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetRoles.Responses.$200>
    /**
     * add_role - Add role
     * 
     * Adds a new role
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.AddRole.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddRole.Responses.$201>
  }
  ['/roles/{name}']: {
    /**
     * get_role_by_name - Find roles by name
     * 
     * Returns the role with the given name if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetRoleByName.Responses.$200>
    /**
     * update_role - Update role
     * 
     * Updates an existing role
     */
    'put'(
      parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
      data?: Paths.UpdateRole.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateRole.Responses.$200>
    /**
     * delete_role - Delete role
     * 
     * Deletes an existing role
     */
    'delete'(
      parameters?: Parameters<Paths.Roles$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteRole.Responses.$200>
  }
  ['/eventactions']: {
    /**
     * get_event_actons - Get event actions
     * 
     * Returns an array with one or more event actions
     */
    'get'(
      parameters?: Parameters<Paths.GetEventActons.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetEventActons.Responses.$200>
    /**
     * add_event_action - Add event action
     * 
     * Adds a new event actions
     */
    'post'(
      parameters?: Parameters<Paths.AddEventAction.QueryParameters> | null,
      data?: Paths.AddEventAction.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddEventAction.Responses.$201>
  }
  ['/eventactions/{name}']: {
    /**
     * get_event_action_by_name - Find event actions by name
     * 
     * Returns the event action with the given name if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Eventactions$Name.PathParameters & Paths.GetEventActionByName.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetEventActionByName.Responses.$200>
    /**
     * update_event_action - Update event action
     * 
     * Updates an existing event action
     */
    'put'(
      parameters?: Parameters<Paths.Eventactions$Name.PathParameters> | null,
      data?: Paths.UpdateEventAction.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateEventAction.Responses.$200>
    /**
     * delete_event_action - Delete event action
     * 
     * Deletes an existing event action
     */
    'delete'(
      parameters?: Parameters<Paths.Eventactions$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteEventAction.Responses.$200>
  }
  ['/eventrules']: {
    /**
     * get_event_rules - Get event rules
     * 
     * Returns an array with one or more event rules
     */
    'get'(
      parameters?: Parameters<Paths.GetEventRules.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetEventRules.Responses.$200>
    /**
     * add_event_rule - Add event rule
     * 
     * Adds a new event rule
     */
    'post'(
      parameters?: Parameters<Paths.AddEventRule.QueryParameters> | null,
      data?: Paths.AddEventRule.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddEventRule.Responses.$201>
  }
  ['/eventrules/{name}']: {
    /**
     * get_event_rile_by_name - Find event rules by name
     * 
     * Returns the event rule with the given name if it exists.
     */
    'get'(
      parameters?: Parameters<Paths.Eventrules$Name.PathParameters & Paths.GetEventRileByName.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetEventRileByName.Responses.$200>
    /**
     * update_event_rule - Update event rule
     * 
     * Updates an existing event rule
     */
    'put'(
      parameters?: Parameters<Paths.Eventrules$Name.PathParameters> | null,
      data?: Paths.UpdateEventRule.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateEventRule.Responses.$200>
    /**
     * delete_event_rule - Delete event rule
     * 
     * Deletes an existing event rule
     */
    'delete'(
      parameters?: Parameters<Paths.Eventrules$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteEventRule.Responses.$200>
  }
  ['/eventrules/run/{name}']: {
    /**
     * run_event_rule - Run an on-demand event rule
     * 
     * The rule's actions will run in background. SFTPGo will not monitor any concurrency and such. If you want to be notified at the end of the execution please add an appropriate action
     */
    'post'(
      parameters?: Parameters<Paths.EventrulesRun$Name.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.RunEventRule.Responses.$202>
  }
  ['/events/fs']: {
    /**
     * get_fs_events - Get filesystem events
     * 
     * Returns an array with one or more filesystem events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
     */
    'get'(
      parameters?: Parameters<Paths.GetFsEvents.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetFsEvents.Responses.$200>
  }
  ['/events/provider']: {
    /**
     * get_provider_events - Get provider events
     * 
     * Returns an array with one or more provider events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
     */
    'get'(
      parameters?: Parameters<Paths.GetProviderEvents.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetProviderEvents.Responses.$200>
  }
  ['/events/log']: {
    /**
     * get_log_events - Get log events
     * 
     * Returns an array with one or more log events applying the specified filters. This API is only available if you configure an "eventsearcher" plugin
     */
    'get'(
      parameters?: Parameters<Paths.GetLogEvents.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetLogEvents.Responses.$200>
  }
  ['/apikeys']: {
    /**
     * get_api_keys - Get API keys
     * 
     * Returns an array with one or more API keys. For security reasons hashed keys are omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.GetApiKeys.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetApiKeys.Responses.$200>
    /**
     * add_api_key - Add API key
     * 
     * Adds a new API key
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.AddApiKey.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddApiKey.Responses.$201>
  }
  ['/apikeys/{id}']: {
    /**
     * get_api_key_by_id - Find API key by id
     * 
     * Returns the API key with the given id, if it exists. For security reasons the hashed key is omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetApiKeyById.Responses.$200>
    /**
     * update_api_key - Update API key
     * 
     * Updates an existing API key. You cannot update the key itself, the creation date and the last use
     */
    'put'(
      parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
      data?: Paths.UpdateApiKey.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateApiKey.Responses.$200>
    /**
     * delete_api_key - Delete API key
     * 
     * Deletes an existing API key
     */
    'delete'(
      parameters?: Parameters<Paths.Apikeys$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteApiKey.Responses.$200>
  }
  ['/admins']: {
    /**
     * get_admins - Get admins
     * 
     * Returns an array with one or more admins. For security reasons hashed passwords are omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.GetAdmins.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetAdmins.Responses.$200>
    /**
     * add_admin - Add admin
     * 
     * Adds a new admin. Recovery codes and TOTP configuration cannot be set using this API: each admin must use the specific APIs
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.AddAdmin.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddAdmin.Responses.$201>
  }
  ['/admins/{username}']: {
    /**
     * get_admin_by_username - Find admins by username
     * 
     * Returns the admin with the given username, if it exists. For security reasons the hashed password is omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetAdminByUsername.Responses.$200>
    /**
     * update_admin - Update admin
     * 
     * Updates an existing admin. Recovery codes and TOTP configuration cannot be set/updated using this API: each admin must use the specific APIs. You are not allowed to update the admin impersonated using an API key
     */
    'put'(
      parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
      data?: Paths.UpdateAdmin.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateAdmin.Responses.$200>
    /**
     * delete_admin - Delete admin
     * 
     * Deletes an existing admin
     */
    'delete'(
      parameters?: Parameters<Paths.Admins$Username.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteAdmin.Responses.$200>
  }
  ['/admins/{username}/2fa/disable']: {
    /**
     * disable_admin_2fa - Disable second factor authentication
     * 
     * Disables second factor authentication for the given admin. This API must be used if the admin loses access to their second factor auth device and has no recovery codes
     */
    'put'(
      parameters?: Parameters<Paths.Admins$Username2faDisable.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DisableAdmin2fa.Responses.$200>
  }
  ['/admins/{username}/forgot-password']: {
    /**
     * admin_forgot_password - Send a password reset code by email
     * 
     * You must set up an SMTP server and the account must have a valid email address, in which case SFTPGo will send a code via email to reset the password. If the specified admin does not exist, the request will be silently ignored (a success response will be returned) to avoid disclosing existing admins
     */
    'post'(
      parameters?: Parameters<Paths.Admins$UsernameForgotPassword.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AdminForgotPassword.Responses.$200>
  }
  ['/admins/{username}/reset-password']: {
    /**
     * admin_reset_password - Reset the password
     * 
     * Set a new password using the code received via email
     */
    'post'(
      parameters?: Parameters<Paths.Admins$UsernameResetPassword.PathParameters> | null,
      data?: Paths.AdminResetPassword.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AdminResetPassword.Responses.$200>
  }
  ['/users']: {
    /**
     * get_users - Get users
     * 
     * Returns an array with one or more users. For security reasons hashed passwords are omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.GetUsers.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUsers.Responses.$200>
    /**
     * add_user - Add user
     * 
     * Adds a new user.Recovery codes and TOTP configuration cannot be set using this API: each user must use the specific APIs
     */
    'post'(
      parameters?: Parameters<Paths.AddUser.QueryParameters> | null,
      data?: Paths.AddUser.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddUser.Responses.$201>
  }
  ['/users/{username}']: {
    /**
     * get_user_by_username - Find users by username
     * 
     * Returns the user with the given username if it exists. For security reasons the hashed password is omitted in the response
     */
    'get'(
      parameters?: Parameters<Paths.Users$Username.PathParameters & Paths.GetUserByUsername.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserByUsername.Responses.$200>
    /**
     * update_user - Update user
     * 
     * Updates an existing user and optionally disconnects it, if connected, to apply the new settings. The current password will be preserved if the password field is omitted in the request body. Recovery codes and TOTP configuration cannot be set/updated using this API: each user must use the specific APIs
     */
    'put'(
      parameters?: Parameters<Paths.Users$Username.PathParameters & Paths.UpdateUser.QueryParameters> | null,
      data?: Paths.UpdateUser.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateUser.Responses.$200>
    /**
     * delete_user - Delete user
     * 
     * Deletes an existing user
     */
    'delete'(
      parameters?: Parameters<Paths.Users$Username.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteUser.Responses.$200>
  }
  ['/users/{username}/2fa/disable']: {
    /**
     * disable_user_2fa - Disable second factor authentication
     * 
     * Disables second factor authentication for the given user. This API must be used if the user loses access to their second factor auth device and has no recovery codes
     */
    'put'(
      parameters?: Parameters<Paths.Users$Username2faDisable.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DisableUser2fa.Responses.$200>
  }
  ['/users/{username}/forgot-password']: {
    /**
     * user_forgot_password - Send a password reset code by email
     * 
     * You must configure an SMTP server, the account must have a valid email address and must not have the "reset-password-disabled" restriction, in which case SFTPGo will send a code via email to reset the password. If the specified user does not exist, the request will be silently ignored (a success response will be returned) to avoid disclosing existing users
     */
    'post'(
      parameters?: Parameters<Paths.Users$UsernameForgotPassword.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UserForgotPassword.Responses.$200>
  }
  ['/users/{username}/reset-password']: {
    /**
     * user_reset_password - Reset the password
     * 
     * Set a new password using the code received via email
     */
    'post'(
      parameters?: Parameters<Paths.Users$UsernameResetPassword.PathParameters> | null,
      data?: Paths.UserResetPassword.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UserResetPassword.Responses.$200>
  }
  ['/status']: {
    /**
     * get_status - Get status
     * 
     * Retrieves the status of the active services
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetStatus.Responses.$200>
  }
  ['/dumpdata']: {
    /**
     * dumpdata - Dump data
     * 
     * Backups data as data provider independent JSON. The backup can be saved in a local file on the server, to avoid exposing sensitive data over the network, or returned as response body. The output of dumpdata can be used as input for loaddata
     */
    'get'(
      parameters?: Parameters<Paths.Dumpdata.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.Dumpdata.Responses.$200>
  }
  ['/loaddata']: {
    /**
     * loaddata_from_file - Load data from path
     * 
     * Restores SFTPGo data from a JSON backup file on the server. Objects will be restored one by one and the restore is stopped if a object cannot be added or updated, so it could happen a partial restore
     */
    'get'(
      parameters?: Parameters<Paths.LoaddataFromFile.QueryParameters & Paths.Loaddata.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.LoaddataFromFile.Responses.$200>
    /**
     * loaddata_from_request_body - Load data
     * 
     * Restores SFTPGo data from a JSON backup. Objects will be restored one by one and the restore is stopped if a object cannot be added or updated, so it could happen a partial restore
     */
    'post'(
      parameters?: Parameters<Paths.Loaddata.QueryParameters> | null,
      data?: Paths.LoaddataFromRequestBody.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.LoaddataFromRequestBody.Responses.$200>
  }
  ['/user/changepwd']: {
    /**
     * change_user_password - Change user password
     * 
     * Changes the password for the logged in user
     */
    'put'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.ChangeUserPassword.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.ChangeUserPassword.Responses.$200>
  }
  ['/user/profile']: {
    /**
     * get_user_profile - Get user profile
     * 
     * Returns the profile for the logged in user
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserProfile.Responses.$200>
    /**
     * update_user_profile - Update user profile
     * 
     * Allows to update the profile for the logged in user
     */
    'put'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.UpdateUserProfile.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateUserProfile.Responses.$200>
  }
  ['/user/2fa/recoverycodes']: {
    /**
     * get_user_recovery_codes - Get recovery codes
     * 
     * Returns the recovery codes for the logged in user. Recovery codes can be used if the user loses access to their second factor auth device. Recovery codes are returned unencrypted
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserRecoveryCodes.Responses.$200>
    /**
     * generate_user_recovery_codes - Generate recovery codes
     * 
     * Generates new recovery codes for the logged in user. Generating new recovery codes you automatically invalidate old ones
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GenerateUserRecoveryCodes.Responses.$200>
  }
  ['/user/totp/configs']: {
    /**
     * get_user_totp_configs - Get available TOTP configuration
     * 
     * Returns the available TOTP configurations for the logged in user
     */
    'get'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserTotpConfigs.Responses.$200>
  }
  ['/user/totp/generate']: {
    /**
     * generate_user_totp_secret - Generate a new TOTP secret
     * 
     * Generates a new TOTP secret, including the QR code as png, using the specified configuration for the logged in user
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.GenerateUserTotpSecret.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GenerateUserTotpSecret.Responses.$200>
  }
  ['/user/totp/validate']: {
    /**
     * validate_user_totp_secret - Validate a one time authentication code
     * 
     * Checks if the given authentication code can be validated using the specified secret and config name
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.ValidateUserTotpSecret.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.ValidateUserTotpSecret.Responses.$200>
  }
  ['/user/totp/save']: {
    /**
     * save_user_totp_config - Save a TOTP config
     * 
     * Saves the specified TOTP config for the logged in user
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.SaveUserTotpConfig.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.SaveUserTotpConfig.Responses.$200>
  }
  ['/user/shares']: {
    /**
     * get_user_shares - List user shares
     * 
     * Returns the share for the logged in user
     */
    'get'(
      parameters?: Parameters<Paths.GetUserShares.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserShares.Responses.$200>
    /**
     * add_share - Add a share
     * 
     * Adds a new share. The share id will be auto-generated
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.AddShare.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.AddShare.Responses.$201>
  }
  ['/user/shares/{id}']: {
    /**
     * get_user_share_by_id - Get share by id
     * 
     * Returns a share by id for the logged in user
     */
    'get'(
      parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserShareById.Responses.$200>
    /**
     * update_user_share - Update share
     * 
     * Updates an existing share belonging to the logged in user
     */
    'put'(
      parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
      data?: Paths.UpdateUserShare.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.UpdateUserShare.Responses.$200>
    /**
     * delete_user_share - Delete share
     * 
     * Deletes an existing share belonging to the logged in user
     */
    'delete'(
      parameters?: Parameters<Paths.UserShares$Id.PathParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteUserShare.Responses.$200>
  }
  ['/user/file-actions/copy']: {
  }
  ['/user/file-actions/move']: {
  }
  ['/user/dirs']: {
    /**
     * get_user_dir_contents - Read directory contents
     * 
     * Returns the contents of the specified directory for the logged in user
     */
    'get'(
      parameters?: Parameters<Paths.GetUserDirContents.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.GetUserDirContents.Responses.$200>
    /**
     * create_user_dir - Create a directory
     * 
     * Create a directory for the logged in user
     */
    'post'(
      parameters?: Parameters<Paths.CreateUserDir.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.CreateUserDir.Responses.$201>
    /**
     * rename_user_dir - Rename a directory. Deprecated, use "file-actions/move"
     * 
     * Rename a directory for the logged in user. The rename is allowed for empty directory or for non empty local directories, with no virtual folders inside
     */
    'patch'(
      parameters?: Parameters<Paths.RenameUserDir.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.RenameUserDir.Responses.$200>
    /**
     * delete_user_dir - Delete a directory
     * 
     * Delete a directory and any children it contains for the logged in user
     */
    'delete'(
      parameters?: Parameters<Paths.DeleteUserDir.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteUserDir.Responses.$200>
  }
  ['/user/files']: {
    /**
     * download_user_file - Download a single file
     * 
     * Returns the file contents as response body
     */
    'get'(
      parameters?: Parameters<Paths.DownloadUserFile.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<any>
    /**
     * create_user_files - Upload files
     * 
     * Upload one or more files for the logged in user
     */
    'post'(
      parameters?: Parameters<Paths.CreateUserFiles.QueryParameters> | null,
      data?: Paths.CreateUserFiles.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.CreateUserFiles.Responses.$201>
    /**
     * rename_user_file - Rename a file
     * 
     * Rename a file for the logged in user. Deprecated, use "file-actions/move"
     */
    'patch'(
      parameters?: Parameters<Paths.RenameUserFile.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.RenameUserFile.Responses.$200>
    /**
     * delete_user_file - Delete a file
     * 
     * Delete a file for the logged in user.
     */
    'delete'(
      parameters?: Parameters<Paths.DeleteUserFile.QueryParameters> | null,
      data?: any,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.DeleteUserFile.Responses.$200>
  }
  ['/user/files/upload']: {
    /**
     * create_user_file - Upload a single file
     * 
     * Upload a single file for the logged in user to an existing directory. This API does not use multipart/form-data and so no temporary files are created server side but only a single file can be uploaded as POST body
     */
    'post'(
      parameters?: Parameters<Paths.CreateUserFile.QueryParameters & Paths.CreateUserFile.HeaderParameters> | null,
      data?: Paths.CreateUserFile.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.CreateUserFile.Responses.$201>
  }
  ['/user/files/metadata']: {
    /**
     * setprops_user_file - Set metadata for a file/directory
     * 
     * Set supported metadata attributes for the specified file or directory
     */
    'patch'(
      parameters?: Parameters<Paths.SetpropsUserFile.QueryParameters> | null,
      data?: Paths.SetpropsUserFile.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<Paths.SetpropsUserFile.Responses.$200>
  }
  ['/user/streamzip']: {
    /**
     * streamzip - Download multiple files and folders as a single zip file
     * 
     * A zip file, containing the specified files and folders, will be generated on the fly and returned as response body. Only folders and regular files will be included in the zip
     */
    'post'(
      parameters?: Parameters<UnknownParamsObject> | null,
      data?: Paths.Streamzip.RequestBody,
      config?: AxiosRequestConfig  
    ): OperationResponse<any>
  }
}

export type Client = OpenAPIClient<OperationMethods, PathsDictionary>
