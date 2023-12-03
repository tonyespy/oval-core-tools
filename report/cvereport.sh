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
kernel_rel=""

#########
# USAGE #
#########

usage() {
    printf "\n\e[2GScript: %s.sh\n" ${FUNCNAME%%-*}
    printf "\e[2GUsage: %s.sh [ Options ] \n" ${FUNCNAME%%-*}
    printf "\e[2GOptions:\n\n"
    printf "\e[3G -d, --dir\e[28GDirectory to store CVE Report Data (Default: /tmp/cvereport_files)\n\n"
    printf "\e[3G -k, --krel\e[28GSpecify kernel release\n\n"
    printf "\e[3G -l, --low\e[28GInclude 'low' priority CVEs (Default: False)\n\n"
    printf "\e[3G -m, --medium\e[28GInclude 'medium' priority CVEs (Default: False)\n\n"
    printf "\e[3G -n, --negligible\e[28GInclude 'negligibile' priority CVEs (Default: False)\n\n"
    printf "\e[3G -p, --purge\e[28GPurge existing CVE Report Data Dir (Default: False)\n\n"
    printf "\e[3G -u, --url\e[28GOutput Ubuntu CVE URL (Default: False)\n\n"
    printf "\e[3G -h, --help\e[28GThis message\n\n"
    printf "\e[3G -H, --html\e]28GGenerate per core snap HTML reports\n\n"
    printf "\e[2GExamples:\n\n"
    printf "\e[4GChange location of collected data:\n"
    printf "\e[6G%s.sh -d %s/cvereport_files\n" ${FUNCNAME%%-*} "$HOME"
}


# FIXME: this function should be removed, but it's currently being kept for reference
# in order to illustrate functionality not possible with OVAL data alone (namely being
# able to identify the packages associated with specific CVEs.
#
# $1 = list of space separated OVAL vulnerability IDs
# $2 = summary snap name
# $3 = result_file
# $4 = cve_report
# $5 = cve_summary
process_oval_results() {
    local crit_cnt=0
    local high_cnt=0
    local med_cnt=0
    local low_cnt=0
    local neg_cnt=0

    for i in $1
    do
        printf "CVE entry: %s\n" ${i}
        continue

        edit_str="s/ID/$i/"
        v_str=$(echo "$cve_xpath" | sed -e "$edit_str")

        # FIXME: If may be possible to just strip the trailing 7 '0's from the OVAL def_id to come up
        # with the CVE ID w/out having to parse the XML for each one...
        #cve=$(xmlstarlet sel -n -N x="http://oval.mitre.org/XMLSchema/oval-definitions-5" -t -v "$v_str" $3)
        cve=$(echo $i | cut -d':' -f4 | sed -e 's/\(^.\{4\}\)\(.*\)\(.\{7\}\)/CVE-\1-\2/')
        printf "CVE: %s\n" ${cve}

        cve_json=$(curl -s https://ubuntu.com/security/cves/$cve.json)
        cve_pri=$(echo $cve_json | jq -r '.priority')
        cve_packages=$(echo $cve_json | jq -r '.packages[].name' | tr '\n' ', ' | sed -e 's/,$//')

        if [[ "$cve_pri" = "critical" ]]; then
            ((crit_cnt++))
        elif [[ "$cve_pri" = "high" ]]; then
            ((high_cnt++))
        elif [[ "$cve_pri" = "low" ]]; then
	        ((low_cnt++))

            if [[ "$cve_low" = false ]]; then
                continue
            fi
        elif [[ "$cve_pri" = "medium" ]]; then
            ((med_cnt++))

            if [[ "$cve_med" = false ]]; then
                continue
            fi
        elif [[ "$cve_pri" = "negligible" ]]; then
            ((neg_cnt++))

            if [[ "$cve_neg" = false ]]; then
                continue
            fi
        else
            continue
        fi

        echo "$cve_json" > "$cve_dir/$cve.$cve_pri.json"

        printf "\e[2G - \e[38;2;0;255;0m"
        printf "%s | %s | %s" "$cve" "$cve_pri" "$cve_packages" | tee -a $4

        if [[ "$cve_url" = true ]]; then
            printf " | <https://ubuntu.com/security/%s>\n" "$cve" | tee -a $4
        else
            printf "\n" | tee -a $4
        fi
    done

    # FIXME: "CVE Summary - xenial" can show up twice (once for snapd, once for core)
    # Show counts
    printf "\n\e[2G\e[1m"
    printf "CVE Summary - %s\n" $2 | tee -a $5
    printf "\e[0m"
    printf "\n=============\n" | tee -a $5
    printf "Critical CVEs: %s\n" "$crit_cnt" | tee -a $5
    printf "High CVEs: %s\n" "$high_cnt" | tee -a $5
    printf "Medium CVEs: %s\n" "$med_cnt" | tee -a $5
    printf "Low CVEs: %s\n" "$low_cnt" | tee -a $5
    printf "Neglible CVEs: %s\n" "$neg_cnt" | tee -a $5
}

# $1 = manifest file
# $2 = kernel manifest
process_manifest() {
    local cve_report=""
    local cve_summary=""
    local report_file=""
    local summary_snap=""

    #printf "[Debug]Manifest file: %s\n" $1

    # FIXME: skip manifest.bare* for now, until
    # fixed in snap_manifest.py
    manifest_file=$(basename $1)
    if [[ ${manifest_file} = manifest.bare* ]]; then
        printf "Skipping %s\n" ${manifest_file}
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
        result_file="${oval_dir}/oscap-cve-scan-result-snapd.xml"
        cve_report=${cve_dir}/cve-list-snapd.txt
        cve_summary=${cve_dir}/cve-summary-snapd.txt
        summary_snap="snapd"

        if [[ "$cve_html" = true ]]; then
            report_file="--report ${oval_dir}/oscap-cve-scan-report-snapd.html"
        fi
    else
        result_file="${oval_dir}/oscap-cve-scan-result-${oval_dist}.xml"
        cve_report=${cve_dir}/cve-list-${oval_dist}.txt
        cve_summary=${cve_dir}/cve-summary-${oval_dist}.txt
        summary_snap=${oval_dist}

        if [[ "$cve_html" = true ]]; then
                report_file="--report ${oval_dir}/oscap-cve-scan-report-${oval_dist}.html"
        fi
    fi

    ######################
    # DOWNLOAD OVAL DATA #
    ######################
    oval_uri="https://security-metadata.canonical.com/oval/oci.com.ubuntu.${oval_dist}.cve.oval.xml.bz2"
    oval_file=${oval_dir}/$(basename ${oval_uri//.bz2})
    test_oval=$(curl -slSL --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 -w %{http_code} -o /dev/null ${oval_uri} 2>&1)

    if [[ ! -s ${oval_file} ]]; then
        printf "\n\e[2G\e[1mDownload OVAL Data for CVE scanning to %s\e[0m\n" ${oval_dir}
        printf "\n\e[2G\e[1mDownload OVAL Data to %s\e[0m\n" ${oval_file}

        if [[ ${test_oval:(-3)} -eq 200 ]]; then
            printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Downloading OVAL data for Ubuntu ${SCAN_RELEASE^}\n"
            wget --show-progress --progress=bar:noscroll --no-dns-cache -qO- ${oval_uri}|bunzip2 -d|tee 1>/dev/null ${oval_file}
        elif [[ ${test_oval:(-3)} -eq 404 ]]; then
            printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OVAL data file for Ubuntu ${SCAN_RELEASE^} does not exist. Skipping\n"
        fi

        if [[ ${test_oval:(-3)} -eq 200 && -s ${oval_file} ]]; then
            printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied OVAL data for for ${oval_dist} to ${oval_dir}/$(basename ${oval_uri//.bz2})\n"
        fi
    fi

    ##########################
    # RUN OSCAP OVAL EVAL    #
    ##########################
    report_retval=$(oscap oval eval --result ${result_file} ${report_file} ${oval_dir}/$(basename ${oval_uri//.bz2}) 1> /dev/null)

    # FIXME: add debug flag?
    ${SNAP}/bin/parse_oval_results.py ${result_file} ${oval_dist} ${snap} ${min_cve_pri} | tee -a ${cve_summary}

    # FIXME: add error check
    rm manifest
}

################
# ARGS/OPTIONS #
################

ARGS=$(getopt -o d:k:almnpuhH --long dir:,krel:,all,low,medium,negligible,purge,url,help,html -n ${prog} -- "$@")
eval set -- "$ARGS"
while true ; do
    case "$1" in
        -d|--dir) export cve_dir=${2};shift 2;;
        -k|--krel) export kernel_rel=${2};shift 2;;
        -a|--all) export cve_all=true;shift 1;;
        -n|--negligible) export cve_neg=true;shift 1;;
        -l|--low) export cve_low=true;shift 1;;
        -m|--medium) export cve_med=true;shift 1;;
        -p|--purge) export cve_purge=true;shift 1;;
        -u|--url) export cve_url=true;shift 1;;
        -h|--help) usage;exit 2;;
        -H|--html) export cve_html=true;shift 1;;
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
# - Fix refresh error:
#   "error: cannot install snap file: snap "oval-core-tools" has
#   running apps (cvereport), pids:"
# - Should there be a single meta-summary file?
# - add ignore option (i.e. ignore list of manifest files)
# - Check for existing OVAL CVE files
# - move OVAL results file into manifest /results sub-dir
# - Add a cmdline flag to surpress the manifest associated with this snap's
#   base, if the system being scanned doesn't include it.
#   (NOTE - this won't apply to scanned images, only running systems)
# - Add support to scan an image
# - [snap_manifest.py] add entry for snapd to manifest.snapd
# - Fix priority logic (build an array of priorities to match on startup)
# - Fix all shellcheck errors
# - Unify if/test syntax
# - Unify var quoting/bracing usage
# - Add option to generate HTML report   // cmdline option
# - Explore use of 'export' (i.e. do the local vars all need to be exported?)
cve_xpath="//x:definition[@id='ID']//x:cve"

# Create CVEREPORT Directory to store files
printf "\n\e[2G\e[1mCreate CVE REPORT Data Directory\e[0m\n"

# Remove existing directory if user chose that option
if [[ ${cve_purge} = true ]]; then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Removing existing directory: %s\n" ${cve_dir}
	[[ -d ${cve_dir} ]] && { rm -rf ${cve_dir}; } || { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Existing directory does not exist.\n"; }
	[[ -d ${cve_dir} ]] && { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not remove existing directory %s\n" ${cve_dir}; } || { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Removed existing directory %s\n" ${cve_dir}; }
fi

# Create CVEREPORT directory using a given name
mkdir -p ${cve_dir}
[[ -d ${cve_dir} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${cve_dir}; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${cve_dir};exit; }

# FIXME: these need to be per core snap!!!
manifest_dir=${cve_dir}/manifests
oval_dir=${cve_dir}/oval

# Create MANIFESTS directory
mkdir -p ${manifest_dir}
[[ -d ${manifest_dir} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${manifest_dir}; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${manifest_dir};exit; }

# Create OVAL directory
mkdir -p ${oval_dir}
[[ -d ${oval_dir} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${manifest_dir}; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${oval_dir};exit; }

printf "\n\e[2G\e[1mOpen Vulnerabilities\e[0m\n\n"

# generate manifests
cd ${manifest_dir}
${SNAP}/bin/snap_manifest.py -i

kman=$(ls manifest.*kernel*)

for file in ./* ; do         # Use ./* ... NEVER bare *
  if [ -e "$file" ] ; then   # Check whether file exists.
     process_manifest ${file} ${kman}
  fi
done

# Show elapsed time
printf "\n\e[1mOVAL CVE Report completed in %s\e[0m\n\n" $(TZ=UTC date --date now-${NOW} "+%H:%M:%S")
