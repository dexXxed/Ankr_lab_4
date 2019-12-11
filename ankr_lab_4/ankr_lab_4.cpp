#include <Windows.h>
#include <WinCrypt.h>
#include <iostream>
#include <vector>
#include <string>

using namespace std;

class descriptive_exception : public exception {
public:
	explicit descriptive_exception(const char* message) : msg_(message) {}

	char const* what() const noexcept override { return msg_; }

private:
	const char* msg_;
};

struct csp_alg_properties
{
	PROV_ENUMALGS_EX enumalgs;
	DWORD keyx_key_inc;
	DWORD sig_key_inc;
};

struct block_key_info
{
	DWORD mode;
	DWORD block_byte_size;
	BYTE* iv;
};


void get_csp_containers(HCRYPTPROV handle, std::vector<std::string>& mas)
{
	char buff[4096];
	DWORD tmp = 4096;
	if (!CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_FIRST))
		throw descriptive_exception("in start reading conainers");
	mas.push_back(buff);
	while (CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_NEXT))
		mas.push_back(buff);
	if (GetLastError() != ERROR_NO_MORE_ITEMS)
		throw descriptive_exception("in reading conainers");
}

bool name_in_array(const std::string& name, const std::vector<std::string>& mas)
{
	for (const std::string& a : mas)
		if (a == name)
			return true;
	return false;
}

void get_csp_handler(DWORD csp_type, LPTSTR csp_name, const std::string keyset_name, HCRYPTPROV& handler)
{
	std::vector<std::string> containers;
	if (!CryptAcquireContext(&handler, NULL, csp_name, csp_type, 0))
	{
		if (GetLastError() == 0x80090016L)
			goto mark_create_keycase;
		else
			throw descriptive_exception("in get csp handle with 0 dwFlags");
	}
	get_csp_containers(handler, containers);
	if (name_in_array(keyset_name, containers))
	{
	mark_open_exist_keycase:
		CryptReleaseContext(handler, 0);
		if (!CryptAcquireContext(&handler, (LPCWSTR) keyset_name.c_str(), csp_name, csp_type, 0))
			throw descriptive_exception("in get csp handle with exist key container");
		containers.clear();
		get_csp_containers(handler, containers);
	}
	else
	{
	mark_create_keycase:
		cout << "ctreate " << keyset_name << " keycontainer" << endl;
		CryptReleaseContext(handler, 0);
		if (!CryptAcquireContext(&handler, (LPCWSTR) keyset_name.c_str(), csp_name, csp_type, CRYPT_NEWKEYSET))
		{
			if (GetLastError() == 0x8009000FL)
			{
				//cout << "Key set " << keyset_name << " is already exist, try open" << endl;
				goto mark_open_exist_keycase;
			}
			else
				throw descriptive_exception("in get csp handle with create key container");
		}
	}
}

void get_alg_properties(HCRYPTPROV handler, DWORD alg_id, csp_alg_properties& param)
{
	DWORD dword_size = sizeof(DWORD);
	DWORD param_size = sizeof(param.enumalgs);
	if (!CryptGetProvParam(handler, PP_ENUMALGS_EX, (BYTE*)&param.enumalgs, &param_size, CRYPT_FIRST))
		throw descriptive_exception("in start reading algorithms");
	if (!CryptGetProvParam(handler, PP_KEYX_KEYSIZE_INC, (BYTE*)&param.keyx_key_inc, &dword_size, 0))
		throw descriptive_exception("in start reading keyx_inc");
	if (!CryptGetProvParam(handler, PP_SIG_KEYSIZE_INC, (BYTE*)&param.sig_key_inc, &dword_size, 0))
		throw descriptive_exception("in start reading sig_inc");
	if (param.enumalgs.aiAlgid == alg_id)
		return;
	while (CryptGetProvParam(handler, PP_ENUMALGS_EX, (BYTE*)&param.enumalgs, &param_size, CRYPT_NEXT))
	{
		if (param.enumalgs.aiAlgid == alg_id)
			return;
	}
	DWORD error = GetLastError();
	if (error != ERROR_NO_MORE_ITEMS)
		throw descriptive_exception("in reading algorithms");
	throw descriptive_exception("algorithm_id was not found");
}

void set_key_info(HCRYPTKEY key_handler, const block_key_info& info)
{
	if (!CryptSetKeyParam(key_handler, KP_MODE, (BYTE*)&(info.mode), 0))
		throw descriptive_exception("in set key mode");
	if (!CryptSetKeyParam(key_handler, KP_IV, info.iv, 0))
		throw descriptive_exception("in set key iv");
}


void get_hash(const char* filename, HCRYPTPROV csp_handler, ALG_ID alg_id, HCRYPTKEY key_handler, HCRYPTHASH& hash_handler)
{
	if (!CryptCreateHash(csp_handler, alg_id, key_handler, 0, &hash_handler))
		throw descriptive_exception("create hash");
	FILE* f = fopen(filename, "rb");
	if (!f)
		throw descriptive_exception("open file to read");
	int buff_size = 1024;
	BYTE* buff = new BYTE[buff_size];
	DWORD cur_len;
	while (cur_len = fread(buff, 1, buff_size, f))
		CryptHashData(hash_handler, buff, cur_len, 0);
	delete[] buff;
	fclose(f);
}

void sign_file(const char* filename, HCRYPTPROV csp_handler, ALG_ID hash_id)
{
	HCRYPTHASH hash_handler;
	get_hash(filename, csp_handler, hash_id, 0, hash_handler);
	DWORD sign_len;
	if (!CryptSignHash(hash_handler, AT_SIGNATURE, NULL, 0, NULL, &sign_len))
		throw descriptive_exception("get sign len");
	BYTE* sign_data = new BYTE[sign_len];
	if (!CryptSignHash(hash_handler, AT_SIGNATURE, NULL, 0, sign_data, &sign_len))
		throw descriptive_exception("get sign");
	CryptDestroyHash(hash_handler);
	char signname[FILENAME_MAX];
	sprintf(signname, "%s.sign", filename);
	FILE* f = fopen(signname, "wb");
	if (!f)
		throw descriptive_exception("open file to write");
	fwrite(&sign_len, 1, sizeof(sign_len), f);
	fwrite(sign_data, 1, sign_len, f);
	fclose(f);
	delete[] sign_data;
}

bool verify_file(const char* filename, HCRYPTPROV csp_handler, ALG_ID hash_id)
{
	DWORD sign_len;
	char signname[FILENAME_MAX];
	sprintf(signname, "%s.sign", filename);
	FILE* f = fopen(signname, "rb");
	if (!f)
		throw descriptive_exception("open sign-file to read");
	fread(&sign_len, 1, sizeof(sign_len), f);
	BYTE* sign_data = new BYTE[sign_len];
	fread(sign_data, 1, sign_len, f);
	fclose(f);
	HCRYPTHASH hash_handler;
	get_hash(filename, csp_handler, hash_id, 0, hash_handler);
	HCRYPTKEY pubkey_handler;
	if (!CryptGetUserKey(csp_handler, AT_SIGNATURE, &pubkey_handler))
		throw descriptive_exception("get signature public key");
	BOOL result = CryptVerifySignature(hash_handler, sign_data, sign_len, pubkey_handler, NULL, 0);
	CryptDestroyHash(hash_handler);
	delete[] sign_data;
	return result;
}


int main(int argc, const char** argv)
{
	DWORD csp_type = PROV_RSA_AES;
	auto csp_name = (LPTSTR) MS_ENH_RSA_AES_PROV;
	std::string keyset_name = "dexxxed";
	ALG_ID hash_id = CALG_MD5; // MAC

	HCRYPTPROV csp_handler = 0;

	if (argc == 1)
	{
		cout << "So, welcome to help!" << endl;
		cout << "Bad using, use one of the options below:" << endl;
		cout << "ankr_lab_4.exe sign [file_to_sign]" << endl;
		cout << "ankr_lab_4.exe verify [file_to_verify]" << endl;
		system("pause");
		return -1;
	}
	try
	{
		get_csp_handler(csp_type, csp_name, keyset_name, csp_handler);
		if (!strcmp(argv[1], "sign"))
		{
			sign_file(argv[2], csp_handler, hash_id);
		}
		else if (!strcmp(argv[1], "verify"))
		{
			if (verify_file(argv[2], csp_handler, hash_id))
				cout << "sign correct" << endl;
			else
				cout << "BAD SIGN" << endl;
		}
		else
			throw descriptive_exception("bad 1 argument");
	}
	catch (exception & error) {
		cout << "Error message: " << error.what() << endl;
		cout << "System Error Code: " << GetLastError() << endl;
		cout << "You can read more about System Error Codes here:" <<
			"https://docs.microsoft.com/ru-ru/windows/win32/debug/system-error-codes" << endl;
		system("PAUSE");
		return -1;
	}
	return 0;
}
