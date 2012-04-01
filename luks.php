<?php
/**
 *
 * @license		http://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author		 Marcel Beck <marcel.beck@mbeck.org>
 * @copyright	Copyright (c) 2012 Marcel beck
 * @homepage	 https://github.com/nexeck/php-luks
 *
 * This file is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file. If not, see <http://www.gnu.org/licenses/>.
 *
 */

class Luks {

	/**
	 * @var string
	 */
	private $_uuid;

	/**
	 * @var string
	 */
	private $_cipher_name;

	/**
	 * @var string
	 */
	private $_cipher_mode;

	/**
	 * @var string
	 */
	private $_hash_spec;

	/**
	 * @var string
	 */
	private $_type;

	/**
	 * @var string
	 */
	private $_usage;

	/**
	 * @var string
	 */
	private $_partition;

	/**
	 * @var string
	 */
	private $_mapper;

	/**
	 * @var string
	 */
	private $_status = 'close';

	/**
	 * @var bool
	 */
	private $_is_luks = false;

	/**
	 * @var string
	 */
	private $_password_path;

	/**
	 * @static
	 *
	 * @param $device_mapper
	 *
	 * @return bool
	 */
	public static function is_device_mapper($device_mapper)
	{
		return preg_match('/^\/dev\/mapper\/.+$/i', $device_mapper) ? true : false;
	}

	/**
	 * @static
	 *
	 * @param $device
	 *
	 * @return bool
	 */
	public static function is_device($device)
	{
		return preg_match('/^\/dev\/\w+$/i', $device) ? true : false;
	}

	/**
	 * @static
	 *
	 * @param $partition
	 *
	 * @return bool
	 */
	public static function is_partition($partition)
	{
		return preg_match('/^\/dev\/\w+\d+$/i', $partition) ? true : false;
	}

	/**
	 * @static
	 *
	 * @param $device
	 *
	 * @return bool
	 */
	public static function is_md($device)
	{
		return preg_match('/^\/dev\/md\w+\d+$/i', $device) ? true : false;
	}

	/**
	 * @static
	 *
	 * @param $device
	 *
	 * @return bool
	 */
	public static function is_lvm($device)
	{
		return preg_match('/^\/dev\/dm\w+\d+$/i', $device) ? true : false;
	}

	/**
	 * @static
	 *
	 * @param $partition
	 *
	 * @return bool
	 * @throws Exception
	 */
	public static function is_luks($partition)
	{
		if (self::is_partition($partition) === false)
		{
			throw new Exception('No device');
		}
		$cmd = sprintf('export LANG=C; sudo cryptsetup luksDump %s', $partition);
		@self::exec($cmd, $output, $result);
		if ($result !== 0)
		{
			return false;
		}
		return true;
	}

	/**
	 * @static
	 *
	 * @param $uuid
	 *
	 * @return bool
	 */
	public static function is_uuid($uuid)
	{
		return preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i', $uuid) ? true : false;
	}

	/**
	 * @static
	 * @return bool
	 */
	public static function uuid()
	{
		self::exec("uuid -v 4 -F STR", $output, $result);
		if ($result !== 0)
		{
			return false;
		}
		return $output[0];
	}

	/**
	 * @static
	 *
	 * @param $device
	 *
	 * @throws Exception
	 */
	public static function create_partition($device)
	{
		if (self::is_device($device) === false)
		{
			throw new Exception('No device given');
		}
		if (self::is_partition($device) === true)
		{
			throw new Exception('No device given');
		}
		if (self::is_device_mapper($device) === true)
		{
			throw new Exception('No device given');
		}
		$commands = array();
		//$commands[] = sprintf("sudo omv-initfs -b -t xfs %s >/dev/null 2>&1 &", escapeshellarg($device));
		if (self::is_md($device))
		{
			$commands[] = sprintf('export LANG=C; sudo wipefs -a %1$s', $device);
		}
		elseif (self::is_lvm($device))
		{
			$commands[] = sprintf('export LANG=C; sudo wipefs -a %1$s', $device);
		}
		else
		{
			$commands[] = sprintf('export LANG=C; sudo dd if=/dev/zero of=%1$s bs=512 count=4', $device);
			$commands[] = sprintf('export LANG=C; sudo dd if=/dev/zero of=%1$s bs=512 count=2 seek=$(expr $(sudo blockdev --getsize64 %1$s) / 512 - 2)', $device);
			$commands[] = sprintf('export LANG=C; sudo parted --script --align optimal -- %1$s mklabel gpt mkpart primary 2048s 100%', $device);
			$commands[] = sprintf('export LANG=C; sudo partprobe %1$s', $device);
		}

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}
	}

	/**
	 * @static
	 *
	 * @param			$command
	 * @param null $output
	 * @param null $return_var
	 *
	 * @return string
	 */
	public static function exec($command, &$output = NULL, &$return_var = NULL)
	{
		putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin");
		return exec($command, $output, $return_var);
	}

	/**
	 * @param $id
	 */
	public function __construct($id)
	{
		if (self::is_partition($id))
		{
			$this->_partition = $id;
		}
		elseif (self::is_uuid($id))
		{
			$this->_uuid = $id;
		}
		else
		{
			throw new Exception('Need partition or uuid');
		}

		$this->_get_device_data();

		if ($this->_is_luks($this->_partition))
		{
			$this->_get_luks_data();
		}
	}

	public function __destruct()
	{
		if (empty($this->_password_path) === false)
		{
			$this->_delete_password();
		}
	}

	/**
	 * @return bool
	 */
	private function _is_luks()
	{
		return ($this->_is_luks = self::is_luks($this->_partition));
	}

	/**
	 * @return bool
	 */
	private function _get_device_data()
	{
		if (!empty($this->_uuid))
		{
			$cmd = sprintf("export LANG=C; sudo findfs UUID=%s", $this->_uuid);
			@self::exec($cmd, $output, $result);
			if ($result !== 0)
			{
				return false;
			}
			$this->_partition = $output[0];
		}

		unset($output);
		$cmd = sprintf("export LANG=C; sudo blkid -p %s", $this->_partition);
		@self::exec($cmd, $output, $result);
		if ($result !== 0)
		{
			return false;
		}

		// /dev/sdf1: UUID="13785615-a2ed-4ab1-a400-e9d75d382893" VERSION="256" TYPE="crypto_LUKS" USAGE="crypto"
		$regex = '/^(\S+): (.+)$/i';
		if (preg_match($regex, $output[0], $matches) === 0)
		{
			return false;
		}
		$data   = array(
			"devicefile" => $matches[1],
			"uuid"			 => "",
			"type"			 => "",
			"usage"			=> ""
		);
		$output = explode(" ", $matches[2]);
		foreach ($output as $outputk => &$outputv)
		{
			$keyValue = explode("=", $outputv);
			if (count($keyValue) != 2)
			{
				continue;
			}
			$data[strtolower($keyValue[0])] = substr($keyValue[1], 1, -1);
		}

		$this->_partition = $data['devicefile'];
		$this->_uuid      = $data['uuid'];
		$this->_type      = $data['type'];
		$this->_usage     = $data['usage'];
		$this->_mapper    = '/dev/mapper/' . $this->_uuid;

		return true;
	}

	private function _get_luks_data()
	{
		if (empty($this->_partition))
		{
			throw new Exception('No partition');
		}
		if ($this->_is_luks($this->_partition) === false)
		{
			throw new Exception('No luks device');
		}

		$this->dump();

		if (file_exists($this->_mapper))
		{
			$this->_status = 'open';
		}
		else
		{
			$this->_status = 'close';
		}
	}

	/**
	 * @return string
	 */
	public function check_status()
	{
		if (file_exists($this->_mapper))
		{
			$this->_status = 'open';
		}
		else
		{
			$this->_status = 'close';
		}

		return $this->_status;
	}

	/**
	 * @return Luks
	 * @throws Exception
	 */
	public function dump()
	{
		if ($this->_is_luks($this->_partition) === false)
		{
			throw new Exception('No luks partition');
		}
		$cmd = sprintf("export LANG=C; sudo cryptsetup luksDump %s", $this->_partition);
		@self::exec($cmd, $output, $result);
		if ($result !== 0)
		{
			throw new Exception('Cannot dump luks');
		}

		foreach ($output as $outputk => &$outputv)
		{
			$keyValue = explode(":", $outputv);
			if (count($keyValue) != 2)
			{
				continue;
			}
			switch ($keyValue[0])
			{
				case 'Version':
					break;
				case 'Cipher name':
					$this->_cipher_name = trim($keyValue[1]);
					break;
				case 'Cipher mode':
					$this->_cipher_mode = trim($keyValue[1]);
					break;
				case 'Hash spec':
					$this->_hash_spec = trim($keyValue[1]);
					break;
				case 'UUID':
					$this->_uuid;
					break;
			}
		}
		return $this;
	}

	/**
	 * @param $password
	 *
	 * @throws Exception
	 */
	private function _save_password($password)
	{
		$this->_password_path = '/tmp/' . $this->_uuid . '/password';

		$commands   = array();
		$commands[] = 'sudo mkdir ' . dirname($this->_password_path);
		$commands[] = 'sudo mount -t ramfs ramfs ' . dirname($this->_password_path);
		$commands[] = 'sudo touch ' . $this->_password_path;
		$commands[] = 'sudo echo -n "' . $password . '" | sudo tee ' . $this->_password_path;

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}
	}

	private function _delete_password()
	{
		$commands   = array();
		$commands[] = 'sudo shred -f ' . $this->_password_path;
		$commands[] = 'sudo umount ' . dirname($this->_password_path);
		$commands[] = 'sudo rmdir ' . dirname($this->_password_path);

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}
	}

	/**
	 * Format luks Device
	 *
	 * @example $luks->format('twofish-cbc-essiv:sha256', 512, 'xfs', 'pass');
	 *
	 * @param $algorithm
	 * @param $keysize
	 * @param $type
	 * @param $password
	 */
	public function format($algorithm, $keysize, $type, $password)
	{
		if ($this->_is_luks($this->_partition))
		{
			throw new Exception('Wont format existing luks partition');
		}

		$this->_uuid = self::uuid();

		$this->_save_password($password);

		$commands   = array();
		$commands[] = 'sudo cryptsetup -q luksFormat -c ' . $algorithm . ' -s ' . $keysize . ' ' . $this->_partition . ' -d ' . $this->_password_path;
		$commands[] = 'sudo cryptsetup luksOpen ' . $this->_partition . ' -d ' . $this->_password_path . ' luksFormat' . $this->_uuid;
		$commands[] = 'sudo mkfs.' . $type . ' /dev/mapper/luksFormat' . $this->_uuid;
		$commands[] = 'sudo cryptsetup luksClose luksFormat' . $this->_uuid;

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}

		$this->_delete_password();
		$this->_get_luks_data();
	}

	/**
	 * Open luks device
	 *
	 * @param $password
	 */
	public function open($password)
	{
		if ($this->_is_luks($this->_partition) === false)
		{
			throw new Exception('No luks partition');
		}

		if ($this->check_status() !== 'close')
		{
			throw new Exception('Luks partition is not close');
		}

		$this->_save_password($password);

		$commands   = array();
		$commands[] = 'sudo cryptsetup luksOpen ' . $this->_partition . ' -d ' . $this->_password_path . ' ' . $this->_uuid;

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}

		$this->_delete_password();

		$this->_status = 'open';
	}

	/**
	 * Close luks device
	 */
	public function close()
	{
		if ($this->_is_luks($this->_partition) === false)
		{
			throw new Exception('No luks partition');
		}

		if ($this->check_status() !== 'open')
		{
			throw new Exception('Luks partition is not open');
		}

		$commands   = array();
		$commands[] = 'sudo cryptsetup luksClose ' . $this->_uuid;

		foreach ($commands as $command)
		{
			@self::exec($command, $output, $result);
			if ($result !== 0)
			{
				throw new Exception('Failed command: ' . $command . ' Result: ' . $result . ' Output: ' . json_encode($output));
			}
		}

		$this->_status = 'close';
	}

} // End Luks

