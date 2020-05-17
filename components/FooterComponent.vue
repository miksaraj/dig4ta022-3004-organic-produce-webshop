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
</style>

<script>
import { mdbFooter, mdbContainer, mdbRow, mdbCol } from 'mdbvue'
export default {
	name: 'FooterComponent',
	components: {
		mdbFooter,
		mdbContainer,
		mdbRow,
		mdbCol
	}
}
</script>
