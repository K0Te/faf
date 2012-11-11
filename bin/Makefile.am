ACLOCAL_AMFLAGS = -I m4

#=============================================================================
# Program
#=============================================================================

bin_PROGRAMS = faf-dwarf-files faf-chroot-helper
faf_dwarf_files_SOURCES = faf-dwarf-files.c
faf_dwarf_files_LDADD = -lelf

faf_chroot_helper_SOURCES = faf-chroot-helper.c

bin_SCRIPTS = \
	faf-abrt-backtraces \
	faf-abrt-check-reports \
	faf-abrt-dup-bugs \
	faf-abrt-dup-improvements \
	faf-bugzilla \
	faf-bugzilla-pull-attachments \
	faf-bugzilla-pull-bugs \
	faf-bugzilla-pull-comments \
	faf-bugzilla-pull-users \
	faf-btserver-cgi \
	faf-btserver-cluster \
	faf-btserver-commit-actions-bugzilla \
	faf-btserver-create-optimized-backtraces \
	faf-btserver-distance \
	faf-btserver-func-stats \
	faf-btserver-prepare-actions \
	faf-btserver-print-actions \
	faf-c2p \
	faf-cache \
	faf-chroot \
	faf-config \
	faf-convert-lob-structure \
	faf-convert-rhbz \
	faf-create-problems \
	faf-clean-rpms \
	faf-client \
	faf-debuginfo-analyze-build \
	faf-debuginfo-analyze-builds \
	faf-debuginfo-build-debugsources \
	faf-debuginfo-report-bugzilla \
	faf-debuginfo-report-log \
	faf-demangle-existing \
	faf-export-reports \
	faf-fedora-pkgdb \
	faf-fedora-pkgdb-pull-collections \
	faf-fedora-pkgdb-pull-packages \
	faf-fedora-pkgdb-pull-people \
	faf-fixtures \
	faf-fix-inlined \
	faf-funfin-analyze-binary \
	faf-funfin-analyze-build \
	faf-funfin-analyze-builds \
	faf-funfin-report \
	faf-generate-reports-bugzilla \
	faf-hub \
	faf-koji \
	faf-koji-pull-builds \
	faf-koji-pull-rpms \
	faf-koji-pull-tags \
	faf-llvm-build \
	faf-mail \
	faf-refreshrepo \
	faf-report-kerneloops \
	faf-retrace \
	faf-save-reports \
	faf-shell \
	faf-stats-abrt-bugs-closed \
	faf-stats-abrt-bugs-opened \
	faf-stats-abrt-bugs-remaining-opened \
	faf-stats-abrt-crashes \
	faf-stats-abrt-users \
	faf-stats-abrt-development \
	faf-stats-functions \
	faf-stats-problems \
	faf-stats-trends \
	faf-update-crashfn \
	faf-worker

EXTRA_DIST = $(bin_SCRIPTS)

#=============================================================================
# Documentation
#=============================================================================

MAN_TXT = \
	faf-abrt-check-reports.txt \
	faf-bugzilla.txt \
	faf-bugzilla-pull-bugs.txt \
	faf-cache.txt \
	faf-config.txt \
	faf-koji.txt \
	faf-koji-pull-builds.txt

# Generated .html pages
pkgdata_DATA = ${MAN_TXT:%.txt=%.html}

# Manual pages are generated from .txt via Docbook
man1_MANS = ${MAN_TXT:%.txt=%.1}

# Do not distribute neither man pages nor HTML files, distribute the
# source .txt files instead.

EXTRA_DIST += asciidoc.conf $(MAN_TXT)
CLEANFILES = $(pkgdata_DATA) $(man1_MANS)

.xml.1:
	xmlto man $<

.txt.xml: asciidoc.conf
	asciidoc --backend=docbook --doctype=manpage --conf-file asciidoc.conf -afaf_version=$(PACKAGE_VERSION) -o $@ $<

.txt.html: asciidoc.conf
	asciidoc --backend=xhtml11 --doctype=manpage --conf-file asciidoc.conf -afaf_version=$(PACKAGE_VERSION) -o $@ $<