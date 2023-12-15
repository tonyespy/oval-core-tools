#!/bin/bash
# -*- Mode:sh; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright (C) 2023 Canonical Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.f-1
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Start Timer
TZ=UTC export NOW=$(date +%s)sec

################
# SET DEFAULTS #
################

prog=${0##*/}
cve_dir='/tmp/core_cvereport'
cve_html=false
cve_all=false
cve_low=false
cve_med=false
cve_neg=false
cve_purge=false
cve_url=false
min_cve_pri=""
image_path=""
kernel_rel=""
save_reports=false
verbose=false

#########
# USAGE #
#########

usage() {
    printf "\n\e[2GScript: %s.sh\n" ${FUNCNAME%%-*}
    printf "\e[2GUsage: %s.sh [ Options ] \n" ${FUNCNAME%%-*}
    printf "\e[2GOptions:\n\n"
    printf "\e[3G -d, --dir\e[28GDirectory to store CVE Report Data (Default: /tmp/cvereport_files)\n\n"
    printf "\e[3G -i, --image\e[28GUbuntu Core (uncompressed) image path\n\n"
    printf "\e[3G -k, --krel\e[28GSpecify kernel release (e.g. focal, jammy, ...)\n\n"
    printf "\e[3G -l, --low\e[28GInclude 'low' priority CVEs (Default: False)\n\n"
    printf "\e[3G -m, --medium\e[28GInclude 'medium' priority CVEs (Default: False)\n\n"
    printf "\e[3G -n, --negligible\e[28GInclude 'negligibile' priority CVEs (Default: False)\n\n"
    printf "\e[3G -p, --purge\e[28GPurge existing CVE Report Data Dir (Default: False)\n\n"
    printf "\e[3G -u, --url\e[28GOutput Ubuntu CVE URL (Default: False)\n\n"
    printf "\e[3G -h, --help\e[28GThis message\n\n"
    printf "\e[3G -H, --html\e]28GGenerate per core snap HTML reports\n\n"
    printf "\e[3G -s, --save\e]28GSave OVAL results files\n\n"
    printf "\e[3G -v, --verbose\e]28GProduce more verbose output\n\n"
    printf "\e[2GExamples:\n\n"
    printf "\e[4GChange location of collected data:\n"
    printf "\e[6G%s.sh -d %s/cvereport_files\n" ${FUNCNAME%%-*} "$HOME"
}

# $1 = manifest file
process_manifest() {
    local cve_report=""
    local cve_summary=""
    local report_file=""

    #printf "[Debug]Manifest file: %s\n" $1

    # FIXME: skip manifest.bare* for now, until
    # fixed in snap_manifest.py
    manifest_file=$(basename $1)
    if [[ ${manifest_file} = manifest.bare* ]]; then
        if [[ ${verbose} = true ]]; then
            printf "Skipping %s\n" ${manifest_file}
        fi

        return
    fi

    base=$(echo ${manifest_file} | cut -d "." -f 2)
    snap=$(echo ${manifest_file} | cut -d "." -f 3)

    if [[ ${base} = "core" ]]; then
        oval_dist="xenial"
    elif [[ ${base} = "snapd" ]]; then
        oval_dist="xenial"
    elif [[ ${base} = "core18" ]]; then
        oval_dist="bionic"
    elif [[ ${base} = "core20" ]]; then
        oval_dist="focal"
    elif [[ ${base} = "core22" ]]; then
        oval_dist="jammy"
    elif [[ ${base} = "core24" ]]; then
        oval_dist="noble"
    elif [[ ${base} = *kernel* ]]; then
        #printf "[Debug]Kernel base: %s\n" ${base}

        if [[ ! -z ${kernel_rel} ]]; then
            #printf "[Debug] Setting oval_dist for kernel to %s\n" ${kernel_rel}
            oval_dist=${kernel_rel}
        else
            printf "No kernel release specified, skipping %s\n" ${manifest_file}
            return
        fi
    else
        printf "Unsupported manifest release: %s\n" $1
        return
    fi

    #printf "\n\e[2G[Debug]oval_dist is: %s\n" ${oval_dist}

    # FIXME: add error check!
    ln -fs $1 manifest

    if [[ ${manifest_file} = manifest*snapd* ]]; then
        result_file=${oval_dir}/oscap-cve-scan-result-snapd.xml
        cve_report=${cve_dir}/cve-list-snapd.txt
        cve_summary=${cve_dir}/cve-summary-snapd.txt

        if [[ "$cve_html" = true ]]; then
            report_file="--report ${oval_dir}/oscap-cve-scan-report-snapd.html"
        fi
    else
        result_file=${oval_dir}/oscap-cve-scan-result-${snap}.xml
        cve_report=${cve_dir}/cve-list-${snap}.txtb
        cve_summary=${cve_dir}/cve-summary-${snap}.txt

        if [[ "$cve_html" = true ]]; then
            report_file="--report ${oval_dir}/oscap-cve-scan-report-${snap}.html"
        fi
    fi

    ######################
    # DOWNLOAD OVAL DATA #
    ######################
    oval_uri="https://security-metadata.canonical.com/oval/oci.com.ubuntu.esm-apps_${oval_dist}.cve.oval.xml.bz2"
    oval_file=${oval_dir}/$(basename ${oval_uri//.bz2})
    test_oval=$(curl -slSL --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 -w %{http_code} -o /dev/null ${oval_uri} 2>&1)

    if [[ ! -s ${oval_file} ]]; then
        if [[ ${verbose} = true ]]; then
            progress_
            printf "\n\e[2G\e[1mDownload OVAL Data for CVE scanning to %s\e[0m\n" ${oval_dir}
            printf "\n\e[2G\e[1mDownload OVAL Data to %s\e[0m\n" ${oval_file}
        fi

        if [[ ${test_oval:(-3)} -eq 200 ]]; then
            progress_bar=""

            if [[ ${verbose} = true ]]; then
                progress_bar="--show-progress --progress=bar:noscroll"
                printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Downloading OVAL data for Ubuntu ${SCAN_RELEASE^}\n"
            fi
            wget ${progress_bar} --no-dns-cache -qO- ${oval_uri}|bunzip2 -d|tee 1>/dev/null ${oval_file}
        elif [[ ${test_oval:(-3)} -eq 404 ]]; then
            if [[ ${verbose} = true ]]; then
                printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OVAL data file for Ubuntu ${SCAN_RELEASE^} does not exist. Skipping\n"
            fi
        fi

        if [[ ${test_oval:(-3)} -eq 200 && -s ${oval_file} && ${verbose} = true ]]; then
            printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied OVAL data for for ${oval_dist} to ${oval_dir}/$(basename ${oval_uri//.bz2})\n"
        fi
    fi

    ##########################
    # RUN OSCAP OVAL EVAL    #
    ##########################
    report_retval=$(oscap oval eval --result ${result_file} ${report_file} ${oval_dir}/$(basename ${oval_uri//.bz2}) 1> /dev/null)

    # FIXME: add debug flag?
    ${SNAP}/bin/parse_oval_results.py ${result_file} ${oval_dist} ${snap} ${min_cve_pri} | tee -a ${cve_summary}

    # Cleanup
    if [[ ${save_reports} = false ]]; then
        rm -f ${result_file}
    fi

    rm -f manifest
}

# $1 = image file
unpack_image() {
    # cleanup /tmp directories and
    # force umount to clear previous mounts
    mkdir -p /tmp/mnt
    umount -q /tmp/mnt
    rm -rf /tmp/snaps

    # check for Android sparse image (as generated by uc-image)
    if file -b $1 | grep -q "Android\ sparse\ image"; then
        if [[ ${verbose} = true ]]; then
            printf "[Info] Android sparse image detected"
        fi

        simg2img $1 /tmp/temp.img
        mount /tmp/temp.img /tmp/mnt
    else
        if [[ ${verbose} = true ]]; then
            printf "[Info] Regular image detected"
        fi

        output=$(kpartx -l $1)

        # FIXME: this is fragile, and should probably
        # be re-factored
        device=$(echo $output | awk '{print $7}')
        kpartx -as "$1"

        # check for error
        mount /dev/mapper/${device} /tmp/mnt
    fi

    if ! mountpoint -q /tmp/mnt; then
        printf "\e[2G - \e[38;2;0;160;200mERROR\e[0m: Failed to mount: %s\n" ${device}
        exit
    fi

    for file in /tmp/mnt/snaps/* ; do
        name=$(basename ${file})
        curr_dir=/tmp/snaps/${name%%_*snap}/current
        mkdir -p ${curr_dir}

        # printf "[Debug] unpack_image: %s\n" ${file}

        if [[ ! -d ${curr_dir} ]]; then
            printf "Failed to make tmp snap dir %s\n" ${curr_dir}
            exit

        fi

        unsquashfs -quiet -f -d ${curr_dir} -n -no ${file} usr/share/snappy/dpkg.yaml snap/manifest.yaml doc/linux-modules-*/changelog.Debian.gz

    done

    kpartx -ds $1
    umount -q /tmp/mnt
}

################
# ARGS/OPTIONS #
################

ARGS=$(getopt -o d:i:k:almnpuhHsv --long dir:,image:,krel:,all,low,medium,negligible,purge,url,help,html,save,verbose -n ${prog} -- "$@")
eval set -- "$ARGS"
while true ; do
    case "$1" in
        -d|--dir) export cve_dir=${2};shift 2;;
        -i|--image) export image_path=${2};shift 2;;
        -k|--krel) export kernel_rel=${2};shift 2;;
        -a|--all) export cve_all=true;shift 1;;
        -n|--negligible) export cve_neg=true;shift 1;;
        -l|--low) export cve_low=true;shift 1;;
        -m|--medium) export cve_med=true;shift 1;;
        -p|--purge) export cve_purge=true;shift 1;;
        -u|--url) export cve_url=true;shift 1;;
        -h|--help) usage;exit 2;;
        -H|--html) export cve_html=true;shift 1;;
        -s|--save) export save_reports=true;shift 1;;
        -v|--verbose) export verbose=true;shift 1;;
        --) shift;break;;
    esac
done

if [[ ${cve_all} = true ]]; then
    min_cve_pri="untriaged"
elif [[ ${cve_neg} = true ]]; then
    min_cve_pri="negligible"
elif [[ ${cve_low} = true ]]; then
    min_cve_pri="low"
elif [[ ${cve_med} = true ]]; then
    min_cve_pri="medium"
else
    min_cve_pri="high"
fi

########
# TODO #
########
#
# - Fix scanning issue with ARM non-sparse images
#   (e.g. ubuntu-core-22-arm64+raspi.img); issue
#   is that non-x86 images don't include a BIOS
#   boot parition.
# - Debug issue w/zombie oscap probe_textfilecontent54 processes
#   that prevents snap refreshes.
# - [snap_manifest.py] add entry for snapd to manifest.snapd
# - add snap version/revision to CVE Summary heading
# - Should there be a single meta-summary file?
# - add ignore option (i.e. ignore list of manifest files)
# - move OVAL results file into manifest /results sub-dir
# - Add a cmdline flag to surpress the manifest associated with this snap's
#   base, if the system being scanned doesn't include it.
#   (NOTE - this won't apply to scanned images, only running systems)
# - Fix all shellcheck errors
# - Unify if/test syntax
# - Unify var quoting/bracing usage
cve_xpath="//x:definition[@id='ID']//x:cve"

# Verify image exists
if [[ ${image_path} != "" && ! -f ${image_path} ]]; then
    printf "\e[2G - \e[38;2;0;160;200mERROR\e[0m: Image path doesn't exist: %s\n" ${image_path}
    exit
fi

# Create CVEREPORT Directory to store files
if [[ ${verbose} = true ]]; then
    printf "\n\e[2G\e[1mCreate CVE REPORT Data Directory\e[0m\n"
fi

# Remove existing directory if user chose that option
if [[ ${cve_purge} = true ]]; then
    if [[ ${verbose} = true ]]; then
        printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Removing existing directory: %s\n" ${cve_dir}
    fi

	if [[ -d ${cve_dir} ]]; then
        rm -rf ${cve_dir}
    fi

    if [[ -d ${cve_dir} ]]; then
        printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not remove existing directory %s\n" ${cve_dir}
    elif [[ ${verbose} = true ]]; then
        printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Removed existing directory %s\n" ${cve_dir}
    fi
fi

# Create CVEREPORT directory using a given name
mkdir -p ${cve_dir}
if [[ -d ${cve_dir} ]]; then
    if ${verbose} = true ]]; then
        printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${cve_dir}
    fi
else
    printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${cve_dir}
    exit
fi

# FIXME: these need to be per core snap!!!
manifest_dir=${cve_dir}/manifests
oval_dir=${cve_dir}/oval

# Create MANIFESTS directory
mkdir -p ${manifest_dir}
if [[ -d ${manifest_dir} ]]; then
    if [[ ${verbose} = true ]]; then
        printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${manifest_dir}
    fi
else
    printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${manifest_dir}
    exit
fi

# Create OVAL directory
mkdir -p ${oval_dir}
if [[ -d ${oval_dir} ]]; then
    if [[ ${verbose} = true ]]; then
        printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${manifest_dir}
    fi
else
    printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${oval_dir}
    exit
fi

image_opt=""
if [[ ${image_path} != "" ]]; then
    unpack_image ${image_path}

    # FIXME
    image_opt="--dir /tmp/snaps"
fi

printf "\n\e[1mOpen Vulnerabilities\e[0m\n\n"

# generate manifests
cd ${manifest_dir}

${SNAP}/bin/snap_manifest.py --manifest_per_snap ${image_opt}

for file in ./* ; do         # Use ./* ... NEVER bare *
  if [ -e "$file" ] ; then   # Check whether file exists.
     process_manifest ${file}
  fi
done

# cleanup
if [[ -d /tmp/snaps ]]; then
    rm -rf /tmp/snaps
fi

if [[ -d /tmp/temp.img ]]; then
    rm /tmp/temp.img
fi

# Show elapsed time
printf "\n\e[1mOVAL CVE Report completed in %s\e[0m\n\n" $(TZ=UTC date --date now-${NOW} "+%H:%M:%S")
