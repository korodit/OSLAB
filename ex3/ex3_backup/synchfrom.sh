rm -rf code_folder/*
sshpass -p 'aiTMBcRe9D' scp -r root@83.212.111.56:/root/ex3/* /home/ubuntu/workspace/oslab/ex3/code_folder/ &> /dev/null
echo '--- synch FROM end ---'