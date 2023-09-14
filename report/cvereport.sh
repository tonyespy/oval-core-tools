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
cve_low=false
cve_med=false
cve_neg=false
cve_purge=false
cve_url=false
cve_results=""
low_cnt=0
med_cnt=0
hi_cnt=0
crit_cnt=0
neg_cnt=0

#########
# USAGE #
#########

cvereport-Usage() {
    printf "\n\e[2GScript: %s.sh\n" ${FUNCNAME%%-*}
    printf "\e[2GUsage: %s.sh [ Options ] \n" ${FUNCNAME%%-*}
    printf "\e[2GOptions:\n\n"
    printf "\e[3G -d, --dir\e[28GDirectory to store CVE Report Data (Default: /tmp/cvereport_files)\n\n"
    printf "\e[3G -r, --results\e[28GOSCAP/OVAL XML results file\n\n"    
    printf "\e[3G -l, --low\e[28GInclude 'low' priority CVEs (Default: False)\n\n"
    printf "\e[3G -m, --medium\e[28GInclude 'medium' priority CVEs (Default: False)\n\n"
    printf "\e[3G -n, --neglible\e[28GInclude 'neglibile' priority CVEs (Default: False)\n\n"
    printf "\e[3G -p, --purge\e[28GPurge existing CVE Report Data Dir (Default: False)\n\n"
    printf "\e[3G -u, --url\e[28GOutput Ubuntu CVE URL (Default: False)\n\n"
    printf "\e[3G -h, --help\e[28GThis message\n\n"
    printf "\e[2GExamples:\n\n"
    printf "\e[4GChange location of collected data:\n"
    printf "\e[6G%s.sh -d %s/cvereport_files\n" ${FUNCNAME%%-*} "$HOME"
};export -f cvereport-Usage

################
# ARGS/OPTIONS #
################

ARGS=$(getopt -o d:r:lmnpuh --long dir:,low,medium,neglible,purge,results,url,help -n ${prog} -- "$@")
eval set -- "$ARGS"
while true ; do
    case "$1" in
        -d|--dir) export cve_dir=${2};shift 2;;
        -r|--results) export cve_results=${2};shift 2;;        
        -l|--low) export cve_low=true;shift 1;;
        -m|--medium) export cve_med=true;shift 1;;
        -n|--neglible) export cve_neg=true;shift 1;;
        -p|--purge) export cve_purge=true;shift 1;;
        -u|--url) export cve_url=true;shift 1;;
        -h|--help) cvereport-Usage;exit 2;;
        --) shift;break;;
    esac
done

########
# TODO #
########
#
# - Check for oscap binary, if not found, ERROR
# - Check for local snap_manifest.py OR oval-core-tools snap, set cmd=
# - Run snap_manifest.py
# - For each manifest.* file
#   - check for OVAL file, if not found, if -O is set, download it
#   -
# - Add a cmdline flag to surpress the manifest associated with the snap's
#   base, if the image being scanned doesn't include it.
# - Add support for ocap scan from ossa.sh    // cmdline option
# - Write oscap HTML report   // cmdline option
# - Write oscap XML result    // cmdline option
# - Filter CVE packages using manifest (i.e. no need to show every version of python)  // cmdline option
# - Fix priority logic (build an array of priorities to match on startup)
# - Fix all shellcheck errors
# - Unify if/test syntax
# - Unify var quoting/bracing usage
# - Add option to generate HTML report   // cmdline option
# - Explore use of 'export' (i.e. do the local vars all need to be exported?)

cve_xpath="//x:definition[@id='ID']//x:cve"

if [[ ! -f ${cve_results} ]]; then
    printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: OSCAP/OVAL XML results file %s doesn't exist\n" ${cve_results}
    exit;
fi

def_ids=$(xmlstarlet sel -n -N x="http://oval.mitre.org/XMLSchema/oval-results-5" -t -v "//x:definition[@result='true']/@definition_id" "$cve_results")

# Create CVEREPORT Directory to store files
printf "\n\e[2G\e[1mCreate CVE REPORT Data Directory\e[0m\n"

# Remove existing directory if user chose that option
if [[ ${cve_purge} = true ]]; then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Removing existing directory: %s\n" ${cve_dir}
	[[ -d ${cve_dir} ]] && { rm -rf ${cve_dir}; } || { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Existing directory does not exist.\n"; }
	[[ -d ${cve_dir} ]] && { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not remove existing directory %s\n" ${cve_dir}; } || { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Removed existing directory %s\n" ${cve_dir}; }
fi

# Create CVEREPORT Directory using a given name
#mkdir -p ${cve_dir}/{apt/package-files,apt/release-files,apt/source-files,util-output,manifests,oval_data,reports}
mkdir -p ${cve_dir}
[[ -d ${cve_dir} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory %s\n" ${cve_dir}; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory %s\n" ${cve_dir};exit; }

cve_report=${cve_dir}/cve-list.txt
cve_summary=${cve_dir}/cve-summary.txt

printf "\n\e[2G\e[1mOpen Vulnerabilities\e[0m\n\n"

for i in $def_ids
do
    edit_str="s/ID/$i/"
    v_str=$(echo "$cve_xpath" | sed -e "$edit_str")
    cve=$(xmlstarlet sel -n -N x="http://oval.mitre.org/XMLSchema/oval-definitions-5" -t -v "$v_str" core-poc-results-20230606.xml)
    cve_json=$(curl -s https://ubuntu.com/security/cves/$cve.json)
    cve_pri=$(echo $cve_json | jq -r '.priority')
    cve_packages=$(echo $cve_json | jq -r '.packages[].name' | tr '\n' ', ' | sed -e 's/,$//')

#   printf "cve: %s cve_pri: %s\n" $cve $cve_pri

    if [[ "$cve_pri" = "critical" ]]; then
        ((crit_cnt++))
    elif [[ "$cve_pri" = "high" ]]; then
        ((hi_cnt++))
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
    printf "%s | %s | %s" "$cve" "$cve_pri" "$cve_packages" | tee -a "$cve_report"

    if [[ "$cve_url" = true ]]; then
        printf " | <https://ubuntu.com/security/%s>\n\n" "$cve" | tee -a "$cve_report"
    else 
        printf "\n\n" | tee -a "$cve_report"
    fi
done

# Show counts
printf "\n\e[2G\e[1m"
printf "CVE Summary" | tee -a "$cve_summary"
printf "\e[0m"
printf "\n=============\n" | tee -a "$cve_summary"
printf "Critical CVEs: %s\n" "$crit_cnt" | tee -a "$cve_summary"
printf "High CVEs: %s\n" "$hi_cnt" | tee -a "$cve_summary"
printf "Medium CVEs: %s\n" "$med_cnt" | tee -a "$cve_summary"
printf "Low CVEs: %s\n" "$low_cnt" | tee -a "$cve_summary"
printf "Neglible CVEs: %s\n" "$neg_cnt" | tee -a "$cve_summary"

# Show elapsed time
printf "\n\e[1mOVAL CVE Report completed in %s\e[0m\n\n" $(TZ=UTC date --date now-${NOW} "+%H:%M:%S")
