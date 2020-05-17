<template>
	<!-- Footer -->
	<mdb-footer class="font-small pt-4 mt-4" id="footer">
		<mdb-container class="text-left">
			<mdb-row>
				<mdb-col md="3">
					<nuxt-link to="/">
						<img
							src="../static/oppia.io_logo_oranssi.png"
							alt="Oppia.io"
							width="152"
							height="48"
						/>
					</nuxt-link>
				</mdb-col>
				<mdb-col md="3">
					<h5 class="title">
						<nuxt-link to="/" class="nav-link">
							Etusivu
						</nuxt-link>
					</h5>
				</mdb-col>
				<mdb-col md="3">
					<h5 class="title">
						<nuxt-link to="/profile" class="nav-link">
							Profiili
						</nuxt-link>
					</h5>
				</mdb-col>
				<mdb-col md="3">
					<h5 class="title">
						<nuxt-link to="/settings" class="nav-link">
							Asetukset
						</nuxt-link>
					</h5>
				</mdb-col>
			</mdb-row>
			<mdb-row v-if="$route.name.includes('chapters-id')">
				<mdb-col>
					<nuxt-link
						v-if="previous !== null"
						:to="previous"
						class="nav-link previous"
					>
						<b-button pill class="btn-primary">
							Edellinen
						</b-button>
					</nuxt-link>
				</mdb-col>
				<mdb-col>
					<nuxt-link
						v-if="next !== null"
						:to="next"
						class="nav-link next"
					>
						<b-button pill class="btn-primary">
							Seuraava
						</b-button>
					</nuxt-link>
				</mdb-col>
			</mdb-row>
		</mdb-container>
		<div class="text-center py-3">
			<mdb-container fluid>
				<p>
					Tämä on harjoitustyö Haaga-Helian kurssilla Digiprojekti
				</p>
				<p>
					Tekijät: Mikko Rajakangas, Jussi Salminen, Markus Masalin,
					Timo Kotilainen
				</p>
			</mdb-container>
		</div>
		<div class="footer-copyright text-center py-3">
			<mdb-container fluid>
				&copy; 2020 Copyright: Oppia.io
			</mdb-container>
		</div>
	</mdb-footer>
	<!-- Footer -->
</template>

<style scoped>
#footer {
	background-color: #3e4551;
	color: whitesmoke;
}
.nav-link {
	color: whitesmoke;
}

.previous {
	float: left;
}

.next {
	float: right;
}
</style>

<script>
import { mapGetters } from 'vuex'
import { mdbFooter, mdbContainer, mdbRow, mdbCol } from 'mdbvue'
export default {
	name: 'FooterComponent',
	components: {
		mdbFooter,
		mdbContainer,
		mdbRow,
		mdbCol
	},
	data() {
		return {
			next: null,
			previous: null
		}
	},
	computed: {
		...mapGetters({
			sectionsByChapter: 'sections/sectionsByChapter'
		})
	},
	watch: {
		$route() {
			const routeName = this.$route.name
			if (routeName.includes('chapters-id')) {
				this.calcNavLinks()
			}
		}
	},
	methods: {
		calcNavLinks() {
			const id = parseInt(this.$route.params.id)
			const sections = this.$store.state.sections.list
			if (this.$route.name === 'chapters-chapters-id') {
				const content = this.sectionsByChapter(
					parseInt(this.$route.params.chapters)
				)
				if (!sections.some(x => x.id === id + 1)) {
					this.next = null
				} else if (!content.some(x => x.id === id + 1)) {
					this.next =
						'/chapters/' +
						(parseInt(this.$route.params.chapters) + 1) +
						'/' +
						(id + 1)
				} else {
					this.next =
						'/chapters/' +
						this.$route.params.chapters +
						'/' +
						(id + 1)
				}
				if (!sections.some(x => x.id === id - 1)) {
					this.previous = null
				} else if (!content.some(x => x.id === id - 1)) {
					this.previous =
						'/chapters/' +
						(parseInt(this.$route.params.chapters) - 1) +
						'/' +
						(id - 1)
				} else {
					this.previous =
						'/chapters/' +
						this.$route.params.chapters +
						'/' +
						(id - 1)
				}
			} else {
				const content = this.$store.state.chapters.list
				if (!content.some(x => x.id === id + 1)) {
					this.next = null
				} else {
					this.next = '/chapters/' + (id + 1)
				}
				if (!content.some(x => x.id === id - 1)) {
					this.previous = null
				} else {
					this.previous = '/chapters/' + (id - 1)
				}
			}
		}
	}
}
</script>
