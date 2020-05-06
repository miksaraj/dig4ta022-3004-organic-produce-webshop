<template>
	<div>
		<b-jumbotron fluid="true" header="Kappaleen otsikko" lead="Alaotsikko">
			<template v-slot:lead>For more information visit website</template>
			<b-button variant="primary" href="#">Tehtävät</b-button>
		</b-jumbotron>
		<b-container fluid="sm">
			<h1>Otsikko</h1>
			<basicText />
			<assignment />
			<basicText />
			<specialText />
			<basicText />
			<multipleChoice />
			<basicText />
			<assignment />
			<basicText />
		</b-container>
	</div>
</template>

<script>
import BasicText from '~/components/BasicText.vue'
import Assignment from '~/components/Assignment.vue'
import SpecialText from '~/components/SpecialText.vue'
import MultipleChoice from '~/components/MultipleChoice.vue'
export default {
	name: 'chapter',
	components: {
		BasicText,
		Assignment,
		SpecialText,
		MultipleChoice
	},
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
