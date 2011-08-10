ACLOCAL_AMFLAGS = -I m4

SUBDIRS = pyfaf

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
	faf-bugzilla-pull-bugs-abrt \
	faf-bugzilla-pull-comments \
	faf-bugzilla-pull-users \
	faf-cache \
	faf-chroot \
	faf-config \
	faf-debuginfo-analyze-build \
	faf-debuginfo-analyze-builds \
	faf-debuginfo-build-debugsources \
	faf-debuginfo-report-bugzilla \
	faf-debuginfo-report-log \
	faf-fedora-pkgdb \
	faf-fedora-pkgdb-pull-collections \
	faf-fedora-pkgdb-pull-packages \
	faf-koji \
	faf-koji-pull-builds \
	faf-koji-pull-rpms \
	faf-koji-pull-tags \
	faf-stats-abrt-bugs-closed \
	faf-stats-abrt-bugs-opened \
	faf-stats-abrt-bugs-remaining-opened \
	faf-stats-abrt-crashes \
	faf-stats-abrt-users \
	faf-stats-abrt-development

EXTRA_DIST = $(bin_SCRIPTS)

#=============================================================================
# Documentation
#=============================================================================

MAN_TXT = \
	faf-abrt-check-reports.txt \
	faf-bugzilla.txt \
	faf-cache.txt \
	faf-config.txt \
	faf-koji.txt \
	faf-bugzilla-pull-bugs-abrt.txt

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

# info manual is generated from TexInfo
info_TEXINFOS = faf.texi
faf_TEXINFOS = fdl.texi

#=============================================================================
# Packaging and distribution
#=============================================================================

EXTRA_DIST += RELEASE faf.spec.in

UPLOAD_URI = klic.name:/home/karel/public_html/ftp.klic.name/public/faf
.PHONY: upload
upload:
	make dist-gzip
	scp $(distdir).tar.gz $(UPLOAD_URI)
	make dist-zip
	scp $(distdir).zip $(UPLOAD_URI)
	make dist-xz
	scp $(distdir).tar.xz $(UPLOAD_URI)

RPM_DIRS = --define "_sourcedir `pwd`" \
           --define "_rpmdir `pwd`" \
           --define "_specdir `pwd`" \
           --define "_builddir `pwd`" \
           --define "_srcrpmdir `pwd`"

rpm: dist-xz faf.spec
	rpmbuild $(RPM_DIRS) -ba faf.spec
srpm: dist-xz faf.spec
	rpmbuild $(RPM_DIRS) -bs faf.spec