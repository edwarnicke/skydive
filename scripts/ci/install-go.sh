#!/bin/bash

set -v

# Set Environment
echo ${PATH} | grep -q "${HOME}/bin" || {
  echo "Adding ${HOME}/bin to PATH"
  export PATH="${PATH}:${HOME}/bin"
}

# Install Go
mkdir -p ~/bin
curl -sL -o ~/bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/bin/gimme
eval "$(gimme 1.7)"

export GOPATH=$WORKSPACE

# Get the Go dependencies
go get -f -u github.com/axw/gocov/gocov
go get -f -u github.com/mattn/goveralls
go get -f -u golang.org/x/tools/cmd/cover
go get -f -u github.com/golang/lint/golint

export PATH=$PATH:$GOPATH/bin

# speedup govendor sync command
REVISION=`curl -q "https://softwarefactory-project.io/r/changes/5923/detail?O=404" | sed '1d' | jq .current_revision | tr -d '"'`
curl -o /tmp/vendor.tgz https://softwarefactory-project.io/r/changes/5923/revisions/$REVISION/archive?format=tgz

pushd ${GOPATH}/src/github.com/skydive-project/skydive
go get -f -u github.com/kardianos/govendor
govendor sync -n | perl -pe 's|fetch \"(.*)\"$|vendor/\1|g' | sort -u > vendor.fetch.list
cat vendor.fetch.list | xargs tar -xvzf /tmp/vendor.tgz --exclude "vendor/vendor.json"
# remove installed
find vendor/ -mindepth 2 -type f | xargs dirname | sort -u > vendor.installed.list
toremove=$(diff -u vendor.fetch.list vendor.installed.list | grep '^\+v' | perl -pe 's|^\+(.*)|\1|')
rm -f "$toremove"
rm -f vendor.fetch.list vendor.installed.list
popd
