# What to backup. 
backup_files="/apl/elk/rundeck/server/data"

# Where to backup to.
dest="/apl/elk/backups/backup-db-rundeck"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-rundeckDB-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
