<template>
	<div>
		<options-row :type="type" />
		<card-deck v-if="view === 'cards'" :items="items" :type="type" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
import OptionsRow from '~/components/OptionsRow.vue'
import CardDeck from '~/components/CardDeck.vue'
import AccordionList from '~/components/AccordionList.vue'
export default {
	components: {
		CardDeck,
		OptionsRow,
		AccordionList
	},
	data() {
		return {
			type: 'modules'
		}
	},
	computed: {
		...mapGetters('modules', ['modulesByCourse']),
		items() {
			return this.modulesByCourse(this.courseId)
		},
		view() {
			return this.$store.state.settings.modulesView
		},
		courseId() {
			return parseInt(this.$route.params.id)
		}
	}
}
</script>
