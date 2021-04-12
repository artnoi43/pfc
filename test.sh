#!/usr/bin/env bash

# For yes/no prompt, and line breaks
# get it at gitlab.com/artnoi-staple/unix/sh-tools/bin/yn.sh

. "$(command -v yn.sh)";
. "$(command -v lb.sh)";

typeset -A name flag ext;

# If you dont want to run certain test functions,
# just prepend a comment (#) OR remove the 'function' keyword

# Tests will be run from top to bottom

function gcm() {
	name[gcm]='pfc: AES GCM (passphrase)';
	flag[gcm]="";
	ext[gcm]='.gcm';
}

encsrc='files/zeroes';
encdst0='/tmp/testpfc';
decdst0='/tmp/zeroes';
gfccmd='python pfc.py';

# Get function names of this file from awk
functions=$(awk '/^function / {print substr($2, 1, length($2)-2)}' $0);

c=0 && for fun in ${functions[@]};
do
	((c++));

	"$fun"\
	&& name="${name[$fun]}"\
	&& encdst="${encdst0}${ext[$fun]}"\
	&& decsrc="${encdst}"\
	&& decdst="${decdst0}${ext[$fun]}"\
	&& alflag="${flag[$fun]}";
	
	simyn "\nRun test ${c} - ${name[$fun]}"\
	|| continue;

	# Encrypt, decrypt, and check diff
	sh -c "${gfccmd} -i ${encsrc} -o ${encdst} ${alflag}";
	sh -c "${gfccmd} -i ${decsrc} -o ${decdst} ${alflag} -d t";
	diff $decdst $encsrc\
	&& printf "\n\n(ok) > ${decdst} == ${encdst}\nfiles match\n\n"\
	|| printf "\n\n(failed):\n${decdst} xx ${encdst}\nfiles differ\n\n";
	simyn "\nFinished test ${name}.\nRemove test files?"\
	&& rm -v "$encdst" "$decdst";
	line;
done;

simyn "\nAll tests done. Remove all test files?"\
&& rm -v "$encdst0"* "$decdst0"*;
