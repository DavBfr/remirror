listen = ":8080"
data = "/var/remirror"

mirrors {
	mirror {
		prefix = "/archlinux/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}

	mirror {
		prefix = "/centos/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}

	mirror {
		prefix = "/fedora/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}

	mirror {
		prefix = "/fedora-epel/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}

	mirror {
		prefix = "/ubuntu/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}

	mirror {
		prefix = "/golang/"
		upstream = "https://storage.googleapis.com"
		matches {
			match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
			match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
			match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
			match { pattern = "-rpm\\.bin$" }
			match { pattern = "\\.xz\\.sig$" }
		}
	}
}
