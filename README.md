# Offensive ELK on Docker

Offensive ELK is a way to ingest and visualize NMap xml data for Redteam engagements.  It will give you the ability to analyze any data set by using the searching/aggregation capabilities of Elasticsearch
and the visualization power of Kibana.  Input data is customizeable by tags that are created by the filename of the NMap XML files.  Now you can finally see an aggregate of your NMap scans in one place, and quickly search for vulnerabilities, view patterns, and identify misconfigurations.

![Image of dashboard](https://gitlab.pg.com/duncan.b/docker-offensive-elk/raw/master/screenshots/dashboard.png?inline=true)

Based on the official Docker images from Elastic:

* [elasticsearch](https://github.com/elastic/elasticsearch-docker)
* [kibana](https://github.com/elastic/kibana-docker)

## Contents

1. [Requirements](#requirements)
   * [Host setup](#host-setup)
   * [SELinux](#selinux)
   * [Docker for Windows](#docker-for-windows)
2. [Usage](#usage)
   * [Bringing up the stack](#bringing-up-the-stack)
   * [Initial setup](#initial-setup)
3. [Configuration](#configuration)
   * [How can I tune the Kibana configuration?](#how-can-i-tune-the-kibana-configuration)
   * [How can I tune the Elasticsearch configuration?](#how-can-i-tune-the-elasticsearch-configuration)
4. [Storage](#storage)
   * [How can I persist Elasticsearch data?](#how-can-i-persist-elasticsearch-data)
5. [Docker Admin Tasks](#docker-admin-tasks)
   * [How can I list containers](#how-can-i-list-containers)
   * [How can I enter a container](#how-can-i-enter-a-container)
   * [How can I view container logs](#how-can-i-view-container-logs)
6. [Resources](#resources)
## Requirements

### Host setup

1. Install [Docker](https://www.docker.com/community-edition#/download) version **17.05+**
2. Install [Docker Compose](https://docs.docker.com/compose/install/) version **1.6.0+**
3. Clone this repository
4. Ingest data (sample data is included in _data/ingestor/samples/)

### SELinux

On distributions which have SELinux enabled out-of-the-box you will need to either re-context the files or set SELinux
into Permissive mode in order for docker-elk to start properly. For example on Redhat and CentOS, the following will
apply the proper context:

```console
$ chcon -R system_u:object_r:admin_home_t:s0 docker-offensive-elk/
```

### Docker for Windows

If you're using Docker for Windows, ensure the "Shared Drives" feature is enabled for the `C:` drive (Docker for Windows > Settings > Shared Drives). See [Configuring Docker for Windows Shared Drives](https://blogs.msdn.microsoft.com/stevelasker/2016/06/14/configuring-docker-for-windows-volumes/) (MSDN Blog).

## Usage

### Bringing up the stack

**Note**: In case you switched branch or updated a base image (or are running this for the first time) - you may need to run `docker-compose build` first

```console
$ docker-compose build
```


Start the stack using `docker-compose`:

```console
$ docker-compose up
```

You can also run all services in the background (detached mode) by adding the `-d` flag to the above command.

Give Kibana a few seconds to initialize, then access the Kibana web UI by hitting
[http://localhost:5601](http://localhost:5601) with a web browser.

By default, the stack exposes the following ports:
* 9200: Elasticsearch HTTP
* 9300: Elasticsearch TCP transport
* 5601: Kibana

**WARNING**: If you're using `boot2docker`, you must access it via the `boot2docker` IP address instead of `localhost`.

**WARNING**: If you're using *Docker Toolbox*, you must access it via the `docker-machine` IP address instead of
`localhost`.

Now that the stack is running, you will want to ingest some data into Elasticsearch. This package contains a sample nmap xml file.  To load data in, using the ingestor, copy XML files to _data/nmap/new. NMap XML files should be named 'app[_tag1_tag2_tag3]_nmap.xml'.  Tags are optional. Adding tags allows filtering and searching in Elasticsearch.  E.g. app_cloud_public_namp.xml, app1_web_nmap.xml, app1_db_nmap.xml

```console
$ cp _data/ingestor/samples/*_nmap.xml _data/ingester/new/
```

## Initial setup

### Default Kibana index pattern creation

When Kibana launches for the first time, it loads the default indices required for NMap data.  The created pattern will automatically be marked as the default index pattern as soon as the Kibana UI is opened for the first time.  Also, an NMap Dashboard is created with some visualizations ready to show-off your data sets.

## Configuration

**NOTE**: Configuration is not dynamically reloaded, you will need to restart the stack after any change in the
configuration of a component.

### How can I tune the Kibana configuration?

The Kibana default configuration is stored in `kibana/config/kibana.yml`.

It is also possible to map the entire `config` directory instead of a single file.

### How can I tune the Elasticsearch configuration?

The Elasticsearch configuration is stored in `elasticsearch/config/elasticsearch.yml`.

You can also specify the options you want to override directly via environment variables:

```yml
elasticsearch:

  environment:
    network.host: "_non_loopback_"
    cluster.name: "my-cluster"
```

## Storage

### How can I persist Elasticsearch data?

The data stored in Elasticsearch will be persisted after container reboot but not after container removal.

In order to persist Elasticsearch data even after removing the Elasticsearch container, you'll have to mount a volume on
your Docker host. Update the `elasticsearch` service declaration to:

```yml
elasticsearch:

  volumes:
    - /path/to/storage:/usr/share/elasticsearch/data
```

This will store Elasticsearch data inside `/path/to/storage`.

**NOTE:** beware of these OS-specific considerations:
* **Linux:** the [unprivileged `elasticsearch` user][esuser] is used within the Elasticsearch image, therefore the
  mounted data directory must be owned by the uid `1000`.
* **macOS:** the default Docker for Mac configuration allows mounting files from `/Users/`, `/Volumes/`, `/private/`,
  and `/tmp` exclusively. Follow the instructions from the [documentation][macmounts] to add more locations.

[esuser]: https://github.com/elastic/elasticsearch-docker/blob/016bcc9db1dd97ecd0ff60c1290e7fa9142f8ddd/templates/Dockerfile.j2#L22
[macmounts]: https://docs.docker.com/docker-for-mac/osxfs/

## Docker Admin Tasks

### How can I list containers

Docker containers can be listed by using the following command:

```console
$ docker ps
```

This command will show 3 running services (elasticsearch, kibana, ingestor).

### How can I enter a container

You can get a shell on a container by using the following command:

```console
$ docker exec -it <image name> /bin/bash
```

### How can I view container logs

You can view container logs by using the following command:

```console
$ docker logs --tail 50 <image name>
```

## Resources

I want to thank the authors and contributors to the following resources for helping me create this project:
* Docker: https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-18-04
* Docker Compose: https://www.digitalocean.com/community/tutorials/how-to-install-docker-compose-on-ubuntu-18-04
* Docker Compose: https://docs.docker.com/compose/install/
* Docker Elk: https://github.com/deviantony/docker-elk
* Docker Offensive Elk Tutorial: https://www.marcolancini.it/2018/blog-elk-for-nmap/
* VulnToES Script: https://github.com/ChrisRimondi/VulntoES
* Directory Monitoring in Python: https://www.michaelcho.me/article/using-pythons-watchdog-to-monitor-changes-to-a-directory
