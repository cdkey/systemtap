// systemtap compile-server server backends.
// Copyright (C) 2017-2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "backends.h"
#include <iostream>
#include <fstream>
#include "../util.h"
#include "utils.h"

extern "C" {
#include <string.h>
#include <glob.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
}

using namespace std;


class default_backend : public backend_base
{
public:
    
    bool can_generate_module(const client_request_data *) {
	return true;
    }
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);
};

int
default_backend::generate_module(const client_request_data *crd,
				 const vector<string> &,
				 const string &,
				 const string &stdout_path,
				 const string &stderr_path)
{
    ofstream stdout_stream, stderr_stream;

    // Create an empty stdout file.
    stdout_stream.open(stdout_path);
    if (stdout_stream.is_open()) {
	stdout_stream.close();
    }

    // Create an stderr file with an error message.
    stderr_stream.open(stderr_path);
    if (stderr_stream.is_open()) {
	stderr_stream << "Error: the server cannot create a module for kernel "
		      << crd->kver << ", architecture " << crd->arch
		      << ", distro " << crd->distro_name << endl;
	stderr_stream.close();
    }
    return 1;
}


class local_backend : public backend_base
{
public:
    local_backend();

    bool can_generate_module(const client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // <kernel version, build tree path>
    map<string, string> supported_kernels;

    string distro_name;

    // The current architecture.
    string arch;
};


local_backend::local_backend()
{
    glob_t globber;
    string pattern = "/lib/modules/*/build";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);

    if (rc) {
	// We weren't able to find any kernel build trees. This isn't
	// a fatal error, since one of the other backends might be
	// able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see
	// kernel build trees installed at startup. If a kernel build
	// tree gets installed after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];

	supported_kernels.insert({kernel_release_from_build_tree(path), path});
    }
    globfree(&globber);

    // Notice we don't error if we can't get the distro name. This
    // isn't a fatal error, since other backends might be able to
    // handle this request.
    vector<string> info;
    get_distro_info(info);
    if (! info.empty()) {
	distro_name = info[0];
	transform(distro_name.begin(), distro_name.end(), distro_name.begin(), ::tolower);
    }

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;
}

bool
local_backend::can_generate_module(const client_request_data *crd)
{
    // See if we support the kernel/arch/distro combination.
    if (supported_kernels.count(crd->kver) == 1 && arch == crd->arch
	&& distro_name == crd->distro_name) {
	return true;
    }

    return false;
}

int
local_backend::generate_module(const client_request_data *crd,
			       const vector<string> &argv,
			       const string &,
			       const string &stdout_path,
			       const string &stderr_path)
{
    // Make sure we're running the correct version of systemtap.
    vector<string> cmd = argv;
    cmd[0] = string(BINDIR) + "/stap";
    return execute_and_capture(2, cmd, crd->env_vars,
			       stdout_path, stderr_path);
}


class container_image_cache
{
public:
    void initialize(const string &buildah_path);
    void add(const string &hash, const string &id);
    bool find(const string &hash, string &id);

private:
    // The buildah executable path.
    string buildah_path;

    mutex image_cache_mutex;
    map<string, string> image_cache;
};


class container_backend : public backend_base
{
public:
    container_backend();

    bool can_generate_module(const client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // The buildah executable path.
    string buildah_path;

    // The container data directory.
    string datadir;
    
    // List of container data filenames. <distro name, path>
    map<string, string> data_files;

    // The current architecture.
    string arch;

    // The script path that builds a container docker file.
    string build_docker_file_script_path;

    container_image_cache image_cache;

    // The current user's uid/gid.
    string uid_gid_str;
};


container_backend::container_backend()
{
    try {
	buildah_path = find_executable("buildah");
	// If find_executable() can't find the path, it returns the
	// name you passed it.
	if (buildah_path == "buildah")
	    buildah_path.clear();
    }
    catch (...) {
	// It really isn't an error for the system to not have the
	// "buildah" executable. We'll just disallow builds using the
	// container backend (down in
	// container_backend::can_generate_module()).
	buildah_path.clear();
    }
    
    image_cache.initialize(buildah_path);

    build_docker_file_script_path = string(PKGLIBDIR)
	+ "/httpd/docker/stap_build_docker_file.py";

    datadir = string(PKGDATADIR) + "/httpd/docker";

    glob_t globber;
    string pattern = datadir + "/*.json";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);
    if (rc) {
	// We weren't able to find any JSON docker data files. This
	// isn't a fatal error, since one of the other backends might
	// be able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see distro
	// json files installed at startup. If one gets installed
	// after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];
	
	size_t found = path.find_last_of("/");
	if (found != string::npos) {
	    // First, get the file basename ("FOO.json").
	    string filename = path.substr(found + 1);

	    // Now, chop off the .json extension.
	    size_t found = filename.find_last_of(".");
	    if (found != string::npos) {
		// Notice we're lowercasing the distro name to make
		// things simpler.
		string distro = filename.substr(0, found);
		transform(distro.begin(), distro.end(), distro.begin(),
			  ::tolower);
		data_files.insert({distro, path});
	    }
	}
    }
    globfree(&globber);

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;

    // Figure out our uid/gid, for use in a "chown" command.
    ostringstream out;
    out << getuid() << ":" << getgid();
    uid_gid_str = out.str();
}

bool
container_backend::can_generate_module(const client_request_data *crd)
{
    // If we don't have a buildah executable, we're done.
    if (buildah_path.empty())
	return false;

    // We have to see if we have a JSON data file for that distro and
    // the arches match.
    if (data_files.count(crd->distro_name) == 1 && arch == crd->arch) {
	return true;
    }

    return false;
}

int
container_backend::generate_module(const client_request_data *crd,
				const vector<string> &argv,
				const string &uuid,
				const string &stdout_path,
				const string &stderr_path)
{
    vector<string> images_to_remove;
    vector<string> containers_to_remove;

    // Handle capturing the container build and run stdout and stderr
    // (along with using /dev/null for stdin). If the client requested
    // it, just use stap's stdout/stderr files.
    string container_stdout_path, container_stderr_path;
    if (crd->verbose >= 3) {
	container_stdout_path = stdout_path;
	container_stderr_path = stderr_path;
    }
    else {
	container_stdout_path = crd->server_dir + "/container_stdout";
	container_stderr_path = crd->server_dir + "/container_stderr";
    }

    // Grab a JSON representation of the client_request_data, and
    // write it to a file (so the script that generates the docker
    // file(s) knows what it is supposed to be doing).
    string build_data_path = string(crd->server_dir) + "/build_data.json";
    struct json_object *root = crd->get_json_object();
    server_error(_F("JSON data: %s", json_object_to_json_string(root)));
    ofstream build_data_file;
    build_data_file.open(build_data_path, ios::out);
    build_data_file << json_object_to_json_string(root);
    build_data_file.close();
    json_object_put(root);

    // Put the date and time in the image name. This will make it
    // easier to know which container images we've created (and when
    // they were created).
    //
    // Why 13 characters in the date and time buffer? 4 charaters
    // (year) + 2 charaters (month) + 2 charaters (day) + 2 charaters
    // (hour) + 2 charaters (minute) + 1 charater (null character) = 13
    // characters total.
    char datetime[13] = { '\0' };
    time_t t = time(NULL);
    struct tm tm_result;
    if (gmtime_r(&t, &tm_result) != NULL)
	strftime(&datetime[0], sizeof(datetime), "%Y%m%d%H%M", &tm_result);

    // Note we're creating a new temporary directory here. This is so
    // that if we reuse the container we're about to build, no files
    // from this run could "leak" over into a new run with the same
    // container.
    string docker_tmpdir_path = crd->server_dir + "/docker_file";
    if (mkdir(docker_tmpdir_path.c_str(), 0700) != 0) {
	// Return an error.
	server_error(_F("mkdir(%s) failed: %s", docker_tmpdir_path.c_str(),
			strerror(errno)));
	return -1;
    }

    vector<string> cmd_args;
#if defined(PYTHON3_EXISTS)
    cmd_args.push_back(PYTHON3_BASENAME);
#elif defined(PYTHON_EXISTS)
    cmd_args.push_back(PYTHON_BASENAME);
#else
#error "Couldn't find python version 2 or 3."
#endif
    cmd_args.push_back(build_docker_file_script_path);
    cmd_args.push_back("--distro-file");
    cmd_args.push_back(data_files[crd->distro_name]);
    cmd_args.push_back("--build-file");
    cmd_args.push_back(build_data_path);
    cmd_args.push_back("--data-dir");
    cmd_args.push_back(datadir);
    cmd_args.push_back("--dest-dir");
    cmd_args.push_back(docker_tmpdir_path);
    int rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				 container_stdout_path, container_stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error(_F("%s failed.",
			build_docker_file_script_path.c_str()));
	return -1;
    }

    string docker_file_path = docker_tmpdir_path + "/base.docker";
    string hash;
    if (get_file_hash(docker_file_path, hash) != 0) {
	server_error(_F("unable to has file %s", docker_file_path.c_str()));
	return -1;
    }

    // Note we're using the docker file hash as part of the container
    // name. This will allow us to do a sort of caching, since
    // "buildah" doesn't support caching (like "docker" does).
    //
    // Also note we're using the UUID as part the container image
    // name. This keeps us from trying to build multiple images with
    // the same name at the same time.
    //
    // Finally note we're putting the date and time in the container
    // image name. This will help us when we decide what containers to
    // delete. 
    string stap_image_name = "sourceware.org/" + hash + "/" + uuid +
	":" + datetime;

    // If we can find an image with the same docker file hash, use it
    // instead of building a new image.
    string image_id;
    if (image_cache.find(hash, image_id))
    {
	// We're going to reuse an existing container. Tag the image
	// with the new image name (to help keep track of the last
	// time the image was used).
	cmd_args.clear();
	cmd_args.push_back("sudo");
	cmd_args.push_back(buildah_path);
	cmd_args.push_back("tag");
	cmd_args.push_back(image_id);
	cmd_args.push_back(stap_image_name);
	rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				 container_stdout_path, container_stderr_path);
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("buildah tag failed.");
	    return -1;
	}
    }
    else {
	// Kick off building the container image.
	cmd_args.clear();
	cmd_args.push_back("sudo");
	cmd_args.push_back(buildah_path);
	cmd_args.push_back("bud");
	cmd_args.push_back("-t");
	cmd_args.push_back(stap_image_name);
	cmd_args.push_back("-f");
	cmd_args.push_back(docker_file_path);
	cmd_args.push_back(docker_tmpdir_path);
	rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				 container_stdout_path, container_stderr_path);
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("buildah build failed.");
	    return -1;
	}
	image_cache.add(hash, stap_image_name);
    }

    // We need a unique name for the container that "buildah run stap
    // ..." will create, so grab another uuid.
    string stap_container_uuid = get_uuid();

    // At this point, we've got an image. We need to convert it to a
    // container. Note that instead of copying the user's file(s) into
    // the container, running stap, then copying the resulting file(s)
    // out of the container, we're just going to bind mount the temp
    // directory into the container.
    cmd_args.clear();
    cmd_args.push_back("sudo");
    cmd_args.push_back(buildah_path);
    cmd_args.push_back("from");
    cmd_args.push_back("--name");
    cmd_args.push_back(stap_container_uuid);
    cmd_args.push_back("--volume");
    // The mount options are:
    //    rw: read-write mode
    //    Z: private unshared selinux label (so the host os and
    //       container can privately share the directory)
    cmd_args.push_back(crd->client_dir + ":" + crd->client_dir + ":rw,Z");
    cmd_args.push_back(stap_image_name);
    rc = execute_and_capture(2, cmd_args, vector<std::string> (),
			     stdout_path, stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error("buildah from failed.");
	return -1;
    }

    // If we're here, we built the image and converted it into a
    // container successfully. Now configure the container with
    // environment variables that were sent over from the client (if
    // any) and the right working directory.
    //
    // When running "stap --tmpdir=/tmp/FOO", your current directory
    // needs to be /tmp/FOO for stap to run successfully (for some odd
    // reason).
    cmd_args.clear();
    cmd_args.push_back("sudo");
    cmd_args.push_back(buildah_path);
    cmd_args.push_back("config");
    for (auto i = crd->env_vars.begin(); i < crd->env_vars.end(); ++i) {
	cmd_args.push_back("--env");
	cmd_args.push_back(*i);
    }
    cmd_args.push_back("--workingdir");
    cmd_args.push_back(crd->client_dir);
    cmd_args.push_back(stap_container_uuid);
    rc = execute_and_capture(2, cmd_args, vector<std::string> (),
			     stdout_path, stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error("buildah config failed.");
	return -1;
    }

    // Now start the container and run stap.
    cmd_args.clear();
    cmd_args.push_back("sudo");
    cmd_args.push_back(buildah_path);
    cmd_args.push_back("run");
    cmd_args.push_back(stap_container_uuid);
    cmd_args.push_back("--");
    for (auto it = argv.begin(); it != argv.end(); it++) {
	cmd_args.push_back(*it);
    }
    int saved_rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				       stdout_path, stderr_path);
    server_error(_F("Spawned process returned %d", saved_rc));
    if (saved_rc != 0) {
	server_error("buildah run failed.");
    }

    // We've run stap, and now we need to do some cleanup. Since some
    // files get owned by root, the 'stap-http-server' user will have
    // trouble deleting them. So, let's change owner/group of the
    // files from inside the container (where we're root).
    cmd_args.clear();
    cmd_args.push_back("sudo");
    cmd_args.push_back(buildah_path);
    cmd_args.push_back("run");
    cmd_args.push_back(stap_container_uuid);
    cmd_args.push_back("--");
    cmd_args.push_back("chown");
    cmd_args.push_back("-R");
    cmd_args.push_back(uid_gid_str);
    cmd_args.push_back(crd->client_dir);
    rc = execute_and_capture(2, cmd_args, vector<std::string> (),
			     stdout_path, stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error("buildah run failed.");
    }

    // At this point we've built the container and run stap
    // (successfully or unsuccessfully). We're finished with the
    // container.
    containers_to_remove.push_back(stap_container_uuid);

    // OK, at this point we've created a container, run stap, and
    // copied out any result. Let's do a little cleanup and delete the
    // last layer. We'll leave (for now) the container with all the
    // files, but delete the layer that got created as stap was run
    // (since there is no reuse there).
    //
    // buildah rm/rmi stap_container_uuid
    //
    // Note that we have to remove the containers first, because they
    // depend on the images.

    // FIXME: MORE CLEANUP NEEDED!
    //
    // Note that we're not removing the initial buildah image we built,
    // so if the user turns right around again and builds another
    // script that image will get reused. But, that initial docker
    // image never gets deleted currently. The "buildah images" command
    // knows when an image was created, but not the last time it was
    // used.
    //
    // We might be able to tie in the information from "buildah
    // containers", which lists all containers, and when they were
    // created. Since the containers are short-lived (they just exist
    // to run "stap"), their creation date is really the last used
    // date of the related image. But, of course we delete that
    // container at the end of every run so that info gets deleted. In
    // theory we could leave that container around and every so often
    // run a python script that puts the two bits of information
    // together and deletes images and containers that haven't been
    // used in a while.

    if (! containers_to_remove.empty()) {
	cmd_args.clear();
	cmd_args.push_back("sudo");
	cmd_args.push_back(buildah_path);
	cmd_args.push_back("rm");
	for (auto i = containers_to_remove.begin();
	     i != containers_to_remove.end(); i++) {
	    cmd_args.push_back(*i);
	}
	rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				 container_stdout_path, container_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("buildah rm failed.");
	}
    }
    if (! images_to_remove.empty()) {
	cmd_args.clear();
	cmd_args.push_back("sudo");
	cmd_args.push_back(buildah_path);
	cmd_args.push_back("rmi");
	for (auto i = images_to_remove.begin(); i != images_to_remove.end();
	     i++) {
	    cmd_args.push_back(*i);
	}
	rc = execute_and_capture(2, cmd_args, vector<std::string> (),
				 container_stdout_path, container_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("buildah rmi failed.");
	}
    }
    return saved_rc;
}


void
container_image_cache::initialize(const string &bp)
{
    buildah_path = bp;
    if (buildah_path.empty()) {
	return;
    }

    // Let's go ahead and get a list of the container images on this
    // system. This helps us with our buildah image "cache".
    vector<string> cmd_args;
    ostringstream out;

    cmd_args.push_back("sudo");
    cmd_args.push_back(buildah_path);
    cmd_args.push_back("images");
    cmd_args.push_back("--json");
    if (stap_system_read(0, cmd_args, out) != 0) {
	server_error(_("'buildah images' failed"));
	return;
    }

    // Parse the JSON list of images
    enum json_tokener_error json_error;
    string out_str = out.str();
    json_object *root = json_tokener_parse_verbose(out_str.c_str(),
						   &json_error);
    if (root == NULL) {
	server_error(json_tokener_error_desc(json_error));
	return;
    }

    // The top level object of "build images --json" should be an array.
    if (json_object_get_type(root) != json_type_array) {
	server_error(_("Malformed 'buildah image' JSON output"));
	return;
    }

    // Process each item in the array, which should look like:
    // {
    //   "id": "ID",
    //   "names": [
    //     "sourceware.org/HASH/GUID:DATE",
    //     "sourceware.org/HASH/GUID:DATE"
    //   ]
    // }
    map<string, vector<string>> images;
    for (size_t i = 0; i < (size_t)json_object_array_length(root); i++) {
	json_object *jarr_obj = json_object_array_get_idx(root, i);
	const char* jstr;

	json_type jarr_obj_type = json_object_get_type(jarr_obj);
	switch (jarr_obj_type) {
	case json_type_object:
	    {
		string id;
		vector<string> names;
		json_object_object_foreach(jarr_obj, jkey, jval) {
		    switch (json_object_get_type(jval)) {
		    case json_type_array:
			if (strcmp(jkey, "names") != 0) {
			    server_error(_F("Unexpected string key name \"%s\"",
					    jkey));
			    break;
			}
			for (size_t j = 0;
			     j < (size_t)json_object_array_length(jval);
			     j++) {
			    json_object *jarr_obj2 = json_object_array_get_idx(jval, j);
			    switch (json_object_get_type(jarr_obj2)) {
			    case json_type_string:
				jstr = json_object_get_string(jarr_obj2);
				names.push_back(jstr);
				break;
			    default:
				server_error(_F("Unexpected JSON type %s",
						json_type_to_name(json_object_get_type(jarr_obj2))));
				break;
			    }
			}
			break;
		    case json_type_string:
			jstr = json_object_get_string(jval);
			if (strcmp(jkey, "id") != 0) {
			    server_error(_F("Unexpected string key name \"%s\": \"%s\"", jkey, jstr));
			}
			else {
			    id = jstr;
			}
			break;
		    default:
			server_error(_F("Unexpected JSON type %s",
					json_type_to_name(json_object_get_type(jval))));
			break;
		    }
		}
		if (!id.empty() && !names.empty()) {
		    images.insert({id, names});
		}
	    }
	    break;
	default:
	    server_error(_F("Unexpected JSON type %s",
			    json_type_to_name(jarr_obj_type)));
	    break;
	}
    }
    json_object_put(root);

    // We've now processed all the JSON, and got a list of the image
    // id and names(s). Process this list, looking for systemtap
    // images (and find the systemtap image's hash).
    for (auto i = images.begin(); i != images.end(); i++) {
	for (auto j = i->second.begin(); j != i->second.end(); j++) {
	    vector<string> matches;
	    if (regexp_match((*j),
			     "^sourceware.org/([0-9a-f_]+)/[0-9a-f]+:[0-9]+$",
			     matches) == 0) {
		// Store the hash and id.
		if (matches.size() >= 2) {
		    add(matches[1], (i->first));
		}
	    }
	}
    }
}


void
container_image_cache::add(const string &hash, const string &id)
{
    {
	// Use a lock_guard to ensure the mutex gets released even if
	// an exception is thrown.
	lock_guard<mutex> lock(image_cache_mutex);
	image_cache.insert({hash, id});
    }
}


bool
container_image_cache::find(const string &hash, string &id)
{
    {
	// Use a lock_guard to ensure the mutex gets released even if
	// an exception is thrown.
	lock_guard<mutex> lock(image_cache_mutex);
	auto it = image_cache.find(hash);
	if (it != image_cache.end()) {
	    id = it->second;
	    return true;
	}
    }
    id.clear();
    return false;
}


static vector<backend_base *>saved_backends;
static void backends_atexit_handler()
{
    if (!saved_backends.empty()) {
	for (auto it = saved_backends.begin(); it != saved_backends.end();
	     it++) {
	    delete *it;
	}
	saved_backends.clear();
    }
}

void
get_backends(vector<backend_base *> &backends)
{
    std::atexit(backends_atexit_handler);
    if (saved_backends.empty()) {
	// Note that order *is* important here. We want to try the
	// local backend first (since it would be the fastest), then
	// the container backend, and finally the default backend
	// (which just returns an error).
	saved_backends.push_back(new local_backend());
	saved_backends.push_back(new container_backend());
	saved_backends.push_back(new default_backend());
    }
    backends.clear();
    backends = saved_backends;
}
