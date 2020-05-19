<template>
	<div>
		<h3 v-if="item.header">{{ item.header }}</h3>
		<b-embed
			aspect="16by9"
			:src="item.src"
			:allowfullscreen="item.allowFullScreen"
		/>
		<p v-if="item.description">{{ item.description }}</p>
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'VideoEmbed',
	computed: {
		...mapGetters('content', ['contentById']),
		item() {
			return this.contentById(this.id)
			/**
			 * VideoEmbed -objektin rakenne on seuraavanlainen:
			 * id: int,
			 * header: string (optional)
			 * src: string (linkki)
			 * allowFullScreen: boolean
			 * description: string (kootut selitykset, optional)
			 *
			 * On parempi, että VideoEmbed -objektit ovat omina elementteinään,
			 * koska niiden käsittely on näin helpompaa. Sanoisin, että näin ollen
			 * esimerkiksi content-elementti id:llä 21 (joka on muuten masterissa
			 * TheoryElement -tyyppiä, kun sen varmaan olisi tarkoitus olla Assignment?
			 * - samalla contentId 20:llä on Assignment, kun sen selvästi tulisi olla
			 * TheoryElement. Tarkkana! ;)) tulisi jakaa seuraavaksi kahdeksi objektiksi:
			 * VideoEmbed-objekti: {
			 *  id: xxx,
			 *  header: 'Tee testi ja vastaa kysymykseen',
			 *  src: 'https://www.youtube.com/embed/....',
			 *  allowFullScreen: true/false
			 * },
			 * Assignment-objekti: {
			 *  id: 21,
			 *  header: '',
			 *  description: 'Tee yllä olevan videon testi ja kerro, miten se liittyi tarkkaavaisuuteen',
			 *  placeholder: 'Kirjoita vastauksesi tähän!'
			 * }
			 */
		},
		id() {
			return this.$attrs.id
		}
	}
}
</script>
