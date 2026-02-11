listen = ":8080"
data = "/var/remirror"

mirrors {
	mirror {
		prefix = "/archlinux/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "\\.(db|files|db\\.sig|files\\.sig)(\\.tar\\.(gz|xz|zst))?$" action = "try" }
			match { pattern = "/.*\\.links\\.tar\\.gz$" action = "try" }
		}
	}

	mirror {
		prefix = "/centos/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/fedora/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/fedora-epel/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/ubuntu/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources|Contents-.*|Release|InRelease)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/by-hash/.*$" action = "try" }
		}
	}

	mirror {
		prefix = "/golang/"
		upstream = "https://storage.googleapis.com"
	}
}
