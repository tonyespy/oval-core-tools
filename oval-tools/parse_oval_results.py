#!/bin/env python3

import sys

from enum import Enum
from xml.sax import parse
from xml.sax.handler import ContentHandler

class Priority(Enum):
    CRITICAL   = 6
    HIGH       = 5
    MEDIUM     = 4
    LOW        = 3
    NEGLIGIBLE = 2
    UNTRIAGED  = 1
    UNDEFINED  = 0

    @classmethod
    def pri_from_str(cls, pri_str):
        if pri_str == "critical":
            return cls.CRITICAL
        elif pri_str == "high":
            return cls.HIGH
        elif pri_str == "medium":
            return cls.MEDIUM
        elif pri_str == "low":
            return cls.LOW
        elif pri_str == "negligible":
            return cls.NEGLIGIBLE
        elif pri_str == "untriaged":
            return cls.UNTRIAGED
        else:
            return cls.UNDEFINED

    @classmethod
    def pri_to_str(cls, pri):
        if pri == cls.CRITICAL:
            return "critical"
        elif pri == cls.HIGH:
            return "high"
        elif pri == cls.MEDIUM:
            return "medium"
        elif pri == cls.LOW:
            return "low"
        elif pri == cls.NEGLIGIBLE:
            return "negligible"
        elif pri == cls.UNTRIAGED:
            return "untriaged"
        else:
            return "undefined"

class SVGHandler(ContentHandler):
    def __init__(self):
        super().__init__()
        self.cve_defs = {}
        self.results = {}
        self.defs_done = False
        self.curr_id = ""
        self.critical = 0
        self.high = 0
        self.medium = 0
        self.low = 0
        self.negligible = 0
        self.untriaged = 0
        self.manifest_pkg = {}
        self.test_result = False
        self.true_tests = {}

    def printResults(self):
        printed_list = False

        print (f"CVE Summary - {snap}")
        print ("==========================\n")
        print (f"Critical:\t {self.critical}")
        print (f"High:\t\t {self.high}")
        print (f"Medium:\t\t {self.medium}")
        print (f"Low:\t\t {self.low}")
        print (f"Negligible:\t {self.negligible}")
        print (f"Untriaged:\t {self.untriaged}")
        # TODO: add Total:
        print ("==========================\n")

        # TODO: it would be nice to order the
        # results by priority...
        #
        # FIXME use key, val... items()
        for key, value in self.results.items():
            cve = value["cve"]
            pri = value["priority"]
            crit_list = value["crit_list"]
            pri_str = Priority.pri_to_str(pri)

            # just use the first true <criterion>
            #for crit in crit_list:
            #    text = self.true_tests[crit]
            crit = crit_list[0]
            text = self.true_tests[crit]

            # just use the first <tested_item>
            item_ref = text[0]
            pkg = self.manifest_pkg[item_ref]

            if pri.value >= min_pri.value:
                printed_list = True
                print(f"{cve}\t| {pri_str} | {pkg}")

        if printed_list == True:
            print ("==========================\n")

    def checkPri(self, result):
        pri = result["priority"]

        if pri == Priority.CRITICAL:
            self.critical += 1
        elif pri == Priority.HIGH:
            self.high += 1
        elif pri == Priority.MEDIUM:
            self.medium += 1
        elif pri == Priority.LOW:
            self.low += 1
        elif pri == Priority.NEGLIGIBLE:
            self.negligible += 1
        elif pri == Priority.UNTRIAGED:
            self.untriaged += 1
        else:
            print(f"[Error]: invalid priority: {pri}")

    def updateCounts(self):
        results_len = len(self.results)
        # print(f"[Debug]: # of CVE results: {results_len}")
        #
        # FIXME use key, val... items()
        for key, value in self.results.items():
            self.checkPri(value)

        print("")

    # TODO: add doc to beginning of this func to describe how
    # the parsing works...
    def startElement(self, name, attrs):
        self.name = name

        # stop parsing CVE defs after <results> is found
        if name == "results":
            #print("[Debug] <results> found; done w/defs!")
            self.defs_done = True

        # <definition> is used in two ways:
        #
        # 1. It's used to define vulnerabilities that can exist
        #    in the release.
        # 2. It's used to define results of an oscap OVAL eval report
        #
        # The vulnerabilities always come first, and once <results>
        # has been found, all definitions that follow define the
        # results for each CVE.
        elif name == "definition":
            if self.defs_done != True:
                self.curr_id = attrs["id"]
                #print(f"[Debug] def_id={self.curr_id}")
                self.cve_defs[self.curr_id] = {}
            else:
                result = attrs["result"]
                if result == "true":
                    self.curr_id = attrs["definition_id"]
                    self.results[self.curr_id] = self.cve_defs[self.curr_id]

        elif name == "cve":
            # Note - unfortunately package isn't an attribute
            # or child of <definition>, so it isn't possible
            # to include in each CVE dict entry
            pri_str = attrs["priority"]
            pri = Priority.pri_from_str(pri_str)
            self.cve_defs[self.curr_id] = {"priority": pri}
        elif name == "ind-sys:textfilecontent_item":
            # grab every testfilecontent_item and add
            # to manifest_pkg dict using curr_id as index
            self.curr_id = attrs["id"]
            #print(f"[Debug] textfilecontent_item {self.curr_id}")
        elif name == "test":
            result = attrs["result"]
            if result == "true":
                self.curr_id = attrs["test_id"]
                # FIXME: get rid of Bool; check for existence
                # of dict entry for curr_id
                self.test_result = True
                self.true_tests[self.curr_id] = []
            else:
                self.test_result = False
        elif name == "tested_item":
            result = attrs["result"]
            item_id = attrs["item_id"]

            #
            # NOTE -- the underlying data somtimes has tested_item with
            # result="not evaluated" for <tests> with result=true
            #
            # TODO: try ignoring result of tested_items and see if this
            # makes produces better results
            #
            #print(f"[Debug] <tested_item item_id={item_id} result={result}>")
            #if self.test_result == True and result == "true":
            #if result == "true":
            #    print(f"[Debug] <tested_item item_id={item_id} result=true>")
            #    self.true_tests[self.curr_id].append(item_id)
            if self.test_result == True:
                self.true_tests[self.curr_id].append(item_id)

        # Only grab <criterion> elements from result <defs>
        elif name == "criterion":
            if self.defs_done == True:
                result = attrs["result"]

                if result == "true":
                    test_ref = attrs["test_ref"]

                    if "crit_list" in self.results[self.curr_id]:
                        self.results[self.curr_id]["crit_list"].append(test_ref)
                    else:
                        crit_list = [ test_ref ]
                        self.results[self.curr_id].update({"crit_list": crit_list})

    def endElement(self, name): 
        self.name = ""

        # When </results> is parsed, we're all done
        if name == "results":
            self.updateCounts()
            self.printResults()

    def characters(self, content):
        if self.name == "cve":
            if content.strip() != "":
               self.cve_defs[self.curr_id].update({"cve": content})
        elif self.name == "ind-sys:text":
            # TODO: the content of this elemenet is the package
            # name and version. Maybe drop the version?
            if content.strip() != "":
               self.manifest_pkg[self.curr_id] = content

def main():
    global snap
    global min_pri
    global oval_dist

    n = len(sys.argv)
    if n != 5:
        print("Must specify path to OVAL results file, oval_dist, manifest, and min_cve_pri!")
        return

    results = sys.argv[1]
    oval_dist = sys.argv[2]
    snap = sys.argv[3]
    pri_str = sys.argv[4]
    min_pri = Priority.pri_from_str(pri_str)

    #print(f"[Debug] parse_oval_results: {results} {oval_dist} {manifest_file} {min_pri}\n")
    parse(results, SVGHandler())

if __name__ == "__main__":
    main()
