#!/bin/bash

# a terrible backup system
# uselessness = 8/10

# set -x
# trap "set +x" EXIT

BACKUP_DIR="$HOME/backup"
DATE_FMT="+%Y%m%d-%H%M%S"

create() {
	local NAME=$1
	local SRC=$2
	local DIR="$BACKUP_DIR/$NAME"

	mkdir -p "$DIR"

	(( $? != 0 )) && { echo "error creating directory"; exit 1 ; }

	local DIR_SIZE=$(find "$DIR" -mindepth 1 -maxdepth 1 | wc -l)
	local INDEX=$((DIR_SIZE + 1))
	local BACKUP="${DIR}/backup${INDEX}"
	mkdir "$BACKUP"

	(( $? != 0 )) && { echo "error creating backup"; exit 1 ; }

	cp -vr "${SRC}"* "$BACKUP"

	(( $? != 0 )) && { echo "error creating backup"; exit 1 ; }

	echo "backup${INDEX} created for $NAME"
}

destroy() {
	local NAME=$1
	local DIR="$BACKUP_DIR/$NAME"

	if [[ ! -d "$DIR" ]]; then
		echo "$NAME does not exist"
		exit 1
	fi

	rm -rf "$DIR"

	echo "$NAME destroyed"
}

list_backups() {
	DIR="$1"

	for backup in "$DIR"/*; do
		local name=$(basename "$backup")
		local time=$(date -d "@$(stat -c "%Y" "$backup")" $DATE_FMT)

		printf "%-20s %10s\n" "$name" "$time"
	done
}

list() {
	local NAME=$1
	local DIR=

	if [[ -z "$NAME" ]]; then
		local first=0

		for backup in "$BACKUP_DIR"/*; do
			local name=$(basename "$backup")

			[[ $first == 0 ]] && {
				printf "%s\n" "$name"
				first=1
			} || {
				printf "\n%s\n" "$name"
			}

			[[ -d "$backup" ]] && list_backups "$backup"
		done

		exit 0
	fi

	DIR="$BACKUP_DIR/$NAME"

	if [[ ! -d "$DIR" ]]; then
		echo "$NAME does not exist"
		exit 1
	fi

	list_backups "$DIR"
}

merge() {
	local NAME=$1
	local SRC=$2
	local DIR="$BACKUP_DIR/$NAME"

	if [[ ! -d "$DIR" ]]; then
		echo "$NAME does not exist"
		exit 1
	fi

	local DIR_SIZE=$(find "$DIR" -mindepth 1 -maxdepth 1 | wc -l)

	if ((DIR_SIZE == 0)); then
		echo "there is no backup associated to $NAME"
		exit 1
	fi

	local INDEX=$((DIR_SIZE))
	local BACKUP="${DIR}/backup${INDEX}"

	rsync -avc --delete "${SRC}" "${BACKUP}"
}

print_usage() {
	printf "Usage: %s <command> [BACKUP_NAME] [SRC_DIR]\n\n" $0
	printf "commands: \n\n"
	printf "%-10s %10s\n" "list" "list the existing backups associated with BACKUP_NAME."
	printf "%-10s %10s\n\n" "" "if BACKUP_NAME is omitted, all the backups will be listed"
	printf "%-10s %10s\n\n" "create" "create a new backup associated with BACKUP_NAME"
	printf "%-10s %10s\n\n" "merge" "update the most recent backup associated with BACKUP_NAME"
	printf "%-10s %10s\n" "destroy" "destroy all backups associated with BACKUP_NAME"
}

main() {
	if (( $# == 0)) || (( $# > 3 )); then
		print_usage
		exit 0
	fi

	mkdir -p $BACKUP_DIR

	if (( $? != 0 )); then
		echo "failed to create $BACKUP_DIR"
		exit 1
	fi

	local CMD=$1

	if [[ "${CMD,,}" == "create" ]]; then
		NAME=$2
		SRC=$3

		: "${NAME:?missing backup_name}"
		: "${SRC:?missing src_dir}"

		create "$NAME" "$SRC"
	elif [[ "${CMD,,}" == "destroy" ]]; then
		NAME=$2

		: "${NAME:?missing backup_name}"

		destroy "$NAME"
	elif [[ "${CMD,,}" == "list" ]]; then
		NAME=$2

		list "$NAME"
	elif [[ "${CMD,,}" == "merge" ]]; then
		NAME=$2
		SRC=$3

		: "${NAME:?missing backup_name}"
		: "${SRC:?missing src_dir}"

		merge "$NAME" "$SRC"
	else
		print_usage
		exit 1
	fi
}

main "$@"